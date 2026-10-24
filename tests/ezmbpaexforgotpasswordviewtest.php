<?php
/**
 * The view userpaex/forgotpassword sets the new password of a reset link through the kernel's user/password operation,
 * judges success by the stored hash, compares the new password with the stored hash (not with a new hash), uses a key
 * once, and afterwards does what the kernel does after a password change where the kernel can. Runs the view against
 * stand-ins for the kernel classes it calls, without the kernel and without a database.
 *
 * Run directly with:
 *   php tests/ezmbpaexforgotpasswordviewtest.php
 *
 *  FP-01 - a valid key and a new password: through the operation (no hash written by the view), paex reset, key removed,
 *          the user's sessions ended, the change mail sent, "change password at next sign-in" cleared, nobody signed in
 *  FP-02 - the old password again is refused, also for a salted hash type; nothing changed, the key stays
 *  FP-03 - an operation that did not store the password (a workflow stopped it): no paex reset, the key stays,
 *          no success, no sessions ended
 *  FP-04 - password and confirmation must be the same string ("1e3" is not "1000")
 *  FP-05 - an expired key is removed and refused; an unknown key is refused; nothing changed
 *  FP-06 - a key whose user no longer exists is removed and refused, also when the form is posted
 *  FP-07 - a password posted as an array is no password; no error
 *  FP-08 - the plain form (no key in the address) gives no deprecation
 *  FP-09 - a kernel without expPasswordPolicy and expPasswordChangeRequired: the password is still changed
 */

$withoutPolicy = in_array( '--without-policy', $argv, true );

$failures = 0;
function fpCheck( $ok, $message )
{
    global $failures;
    echo ( $ok ? 'PASS' : 'FAIL' ), ": $message\n";
    if ( !$ok )
        $failures++;
}

class FpLog
{
    public static $calls = array();
    public static function add( $what ) { self::$calls[] = $what; }
    public static function has( $prefix )
    {
        foreach ( self::$calls as $call )
            if ( strpos( $call, $prefix ) === 0 )
                return true;
        return false;
    }
    public static function text() { return implode( ' ', self::$calls ); }
}

class eZINI
{
    public $name;
    public static function instance( $name = 'site.ini' ) { $ini = new self(); $ini->name = $name; return $ini; }
    public function variable( $group, $name )
    {
        if ( $group === 'mbpaexSettings' && $name === 'ForgotPasswordHashLifeTime' )
            return 3600;
        return false;
    }
    public function hasVariable( $group, $name ) { return false; }
}

class eZHTTPTool
{
    public $UseFullUrl = false;
    public static function instance() { return new self(); }
}

class eZForgotPassword
{
    /** @var eZForgotPassword[] */
    public static $keys = array();
    public $data;
    public function __construct( $data ) { $this->data = $data; }
    public static function fetchByKey( $key ) { return isset( self::$keys[$key] ) ? self::$keys[$key] : null; }
    public function attribute( $name ) { return $this->data[$name]; }
    public function remove() { FpLog::add( 'keyRemoved' ); unset( self::$keys[$this->data['hash_key']] ); }
}

class eZUser
{
    /** @var eZUser[] */
    public static $users = array();
    public $data;

    public function __construct( $data ) { $this->data = $data; }
    public static function fetch( $id ) { return isset( self::$users[$id] ) ? clone self::$users[$id] : null; }
    public function attribute( $name ) { return $this->data[$name]; }
    public function setAttribute( $name, $value ) { FpLog::add( "setAttribute:$name" ); $this->data[$name] = $value; }
    public function store() { FpLog::add( 'store' ); }
    public function site() { return 'site'; }
    public function validatePassword( $password ) { return is_string( $password ) && strlen( $password ) >= 3; }
    // a salted hash type: two hashes of the same password differ, authenticate with password_verify()
    public static function createHash( $login, $password, $site, $type ) { return password_hash( $password, PASSWORD_DEFAULT ); }
    public static function authenticateHash( $login, $password, $site, $type, $hash ) { return password_verify( $password, $hash ); }
    public static function setCurrentlyLoggedInUser( $user, $id, $flags = 0 ) { FpLog::add( "signIn:$id" ); }
}

class eZUserOperationCollection
{
    public static $stop = false;
    public static function password( $id, $newPassword )
    {
        FpLog::add( "operation:$id" );
        if ( !self::$stop )
            eZUser::$users[$id]->data['password_hash'] = password_hash( $newPassword, PASSWORD_DEFAULT );
        return array( 'status' => !self::$stop );
    }
}

class eZOperationHandler
{
    public static function operationIsAvailable( $name ) { return $name === 'user_password'; }
    public static function execute( $module, $operation, $params )
    {
        if ( $module === 'user' && $operation === 'password' )
            return eZUserOperationCollection::password( $params['user_id'], $params['new_password'] );
        return null;
    }
}

if ( !$withoutPolicy )
{
    class expPasswordPolicy
    {
        public function __construct( $ini = null ) {}
        public function endOtherSessions( $userID, $keepSessionKey = null ) { FpLog::add( "sessionsEnded:$userID" ); return 2; }
        public function sendChangedMail( $user, $sessionsEnded = null, $otherSessionsSignedOut = false )
        {
            FpLog::add( 'changedMail:' . $user->attribute( 'contentobject_id' ) . ':' . var_export( $sessionsEnded, true ) );
            return true;
        }
        public static function stampCheckEnabled() { return false; }
    }

    class expPasswordChangeRequired
    {
        public static function clear( $user, $source = 'password' )
        {
            FpLog::add( 'changeRequiredCleared:' . $user->attribute( 'contentobject_id' ) . ":$source" );
            return true;
        }
    }
}

class eZAudit { public static function writeAudit( $name, $data ) { FpLog::add( "audit:$name" ); } }

class eZPaEx
{
    public static function getPaEx( $id, $checkIfUserHasDatatype = false ) { return new self(); }
    public function validatePassword( $password ) { return true; }
    public function resetPasswordLastUpdated() { FpLog::add( 'paexReset' ); }
}

class eZTemplate
{
    public static $vars = array();
    public static function factory() { return new self(); }
    public function setVariable( $name, $value ) { self::$vars[$name] = $value; }
    public function hasVariable( $name ) { return array_key_exists( $name, self::$vars ); }
    public function variable( $name ) { return self::$vars[$name]; }
    public function fetch( $template ) { return ''; }
}

class ezpI18n { public static function tr( $context, $text ) { return $text; } }

class FpModule
{
    public $action = null;
    public $parameters = array();
    public function isCurrentAction( $name ) { return $this->action === $name; }
    public function hasActionParameter( $name ) { return array_key_exists( $name, $this->parameters ); }
    public function actionParameter( $name ) { return $this->parameters[$name]; }
}

$notices = array();
set_error_handler( function( $level, $message ) use ( &$notices ) { $notices[] = $message; return true; } );

function fpRun( $hashKey, $action = null, array $parameters = array() )
{
    global $notices;
    FpLog::$calls = array();
    eZTemplate::$vars = array();
    $notices = array();
    $module = new FpModule();
    $module->action = $action;
    $module->parameters = $parameters;
    $Params = array( 'Module' => $module, 'HashKey' => $hashKey );
    try
    {
        ( function() use ( $Params ) { include dirname( __DIR__ ) . '/modules/userpaex/forgotpassword.php'; } )();
    }
    catch ( Throwable $e )
    {
        FpLog::add( 'error:' . get_class( $e ) . ':' . $e->getMessage() );
    }
}

$validKey = str_repeat( 'a', 32 );
$expiredKey = str_repeat( 'b', 32 );
$orphanKey = str_repeat( 'c', 32 );

function fpReset()
{
    global $validKey, $expiredKey, $orphanKey;
    eZUser::$users = array(
        42 => new eZUser( array( 'contentobject_id' => 42, 'login' => 'jane', 'password_hash' => password_hash( 'old-secret', PASSWORD_DEFAULT ), 'password_hash_type' => 7 ) ),
    );
    eZForgotPassword::$keys = array(
        $validKey => new eZForgotPassword( array( 'user_id' => 42, 'hash_key' => $validKey, 'time' => time() - 60 ) ),
        $expiredKey => new eZForgotPassword( array( 'user_id' => 42, 'hash_key' => $expiredKey, 'time' => time() - 7200 ) ),
        $orphanKey => new eZForgotPassword( array( 'user_id' => 99, 'hash_key' => $orphanKey, 'time' => time() - 60 ) ),
    );
    eZUserOperationCollection::$stop = false;
}

function fpStoredPassword( $password )
{
    return password_verify( $password, eZUser::$users[42]->data['password_hash'] );
}

$change = array( 'NewPassword' => 'new-secret', 'NewPasswordConfirm' => 'new-secret' );

if ( $withoutPolicy )
{
    // FP-09, in a process of its own: the classes cannot be taken away from the main run
    fpReset();
    fpRun( $validKey, 'ChangePassword', $change );
    fpCheck( FpLog::has( 'operation:42' ) && fpStoredPassword( 'new-secret' ) && FpLog::has( 'paexReset' ) && FpLog::has( 'keyRemoved' )
             && eZTemplate::$vars['password_changed'] === true && !FpLog::has( 'error:' ),
             'FP-09 without the kernel\'s password policy classes the password is still changed (' . FpLog::text() . ')' );
    exit( $failures ? 1 : 0 );
}

// FP-01
fpReset();
fpRun( $validKey, 'ChangePassword', $change );
fpCheck( FpLog::has( 'operation:42' ) && !FpLog::has( 'setAttribute:password_hash' ) && fpStoredPassword( 'new-secret' )
         && FpLog::has( 'paexReset' ) && FpLog::has( 'keyRemoved' ) && !isset( eZForgotPassword::$keys[$validKey] )
         && FpLog::has( 'sessionsEnded:42' ) && FpLog::has( 'changedMail:42:2' ) && FpLog::has( 'changeRequiredCleared:42:forgotpassword' )
         && !FpLog::has( 'signIn:' ) && eZTemplate::$vars['password_changed'] === true,
         'FP-01 valid key: operation, paex reset, key removed, sessions ended, mail, mark cleared, nobody signed in (' . FpLog::text() . ')' );

// FP-02
fpReset();
fpRun( $validKey, 'ChangePassword', array( 'NewPassword' => 'old-secret', 'NewPasswordConfirm' => 'old-secret' ) );
fpCheck( !FpLog::has( 'operation:' ) && !FpLog::has( 'setAttribute:password_hash' ) && !FpLog::has( 'keyRemoved' )
         && eZTemplate::$vars['newPasswordMustDiffer'] === true && eZTemplate::$vars['password_changed'] === false,
         'FP-02 the old password again is refused for a salted hash type, the key stays (' . FpLog::text() . ')' );

// FP-03
fpReset();
eZUserOperationCollection::$stop = true;
fpRun( $validKey, 'ChangePassword', $change );
fpCheck( FpLog::has( 'operation:42' ) && !FpLog::has( 'paexReset' ) && !FpLog::has( 'keyRemoved' ) && isset( eZForgotPassword::$keys[$validKey] )
         && !FpLog::has( 'sessionsEnded:' ) && !FpLog::has( 'changedMail:' ) && eZTemplate::$vars['password_changed'] === false
         && eZTemplate::$vars['password_form'] === true,
         'FP-03 password not stored: no paex reset, key stays, no success, form again (' . FpLog::text() . ')' );

// FP-04
fpReset();
fpRun( $validKey, 'ChangePassword', array( 'NewPassword' => '1e3', 'NewPasswordConfirm' => '1000' ) );
fpCheck( !FpLog::has( 'operation:' ) && !FpLog::has( 'setAttribute:password_hash' ) && eZTemplate::$vars['newPasswordNotMatch'] === true,
         'FP-04 "1e3" and "1000" do not match (' . FpLog::text() . ')' );

// FP-05
fpReset();
fpRun( $expiredKey, 'ChangePassword', $change );
fpCheck( FpLog::has( 'keyRemoved' ) && eZTemplate::$vars['wrong_key'] === true && !FpLog::has( 'operation:' )
         && !FpLog::has( 'setAttribute:password_hash' ) && fpStoredPassword( 'old-secret' ),
         'FP-05 expired key: removed and refused, nothing changed' );
fpReset();
fpRun( str_repeat( 'd', 32 ), 'ChangePassword', $change );
fpCheck( eZTemplate::$vars['wrong_key'] === true && !FpLog::has( 'operation:' ) && !FpLog::has( 'setAttribute:password_hash' ),
         'FP-05 unknown key: refused, nothing changed' );

// FP-06
fpReset();
fpRun( $orphanKey );
fpCheck( eZTemplate::$vars['wrong_key'] === true && eZTemplate::$vars['password_form'] === false && FpLog::has( 'keyRemoved' ),
         'FP-06 key of a user that is gone: removed and refused (' . FpLog::text() . ')' );
fpReset();
fpRun( $orphanKey, 'ChangePassword', $change );
fpCheck( !FpLog::has( 'error:' ) && !FpLog::has( 'operation:' ) && eZTemplate::$vars['wrong_key'] === true,
         'FP-06 posting the form with that key gives no error (' . FpLog::text() . ')' );

// FP-07
fpReset();
fpRun( $validKey, 'ChangePassword', array( 'NewPassword' => array( 'x' ), 'NewPasswordConfirm' => array( 'x' ) ) );
fpCheck( !FpLog::has( 'error:' ) && !FpLog::has( 'operation:' ) && eZTemplate::$vars['newPasswordNotValidate'] === true,
         'FP-07 a password posted as an array is no password (' . FpLog::text() . ')' );

// FP-08
fpReset();
fpRun( null );
fpCheck( !$notices && !FpLog::has( 'error:' ), 'FP-08 the plain form gives no deprecation (' . implode( ' | ', $notices ) . ')' );

// FP-09
$output = array();
exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( __FILE__ ) . ' --without-policy 2>&1', $output, $status );
echo implode( "\n", $output ), "\n";
fpCheck( $status === 0, 'FP-09 run without the policy classes' );

echo $failures ? "FAIL: $failures\n" : "PASS: all\n";
exit( $failures ? 1 : 0 );
