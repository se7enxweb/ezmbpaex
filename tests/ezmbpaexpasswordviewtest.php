<?php
/**
 * The view userpaex/password changes a password through the kernel's user/password operation, signs the session in
 * only as the user who owns it, and sends posted redirect targets through eZRedirectManager::returnURI(). Runs the
 * view against stand-ins for the kernel classes it calls, without the kernel and without a database.
 *
 * Run directly with:
 *   php tests/ezmbpaexpasswordviewtest.php
 *
 *  PW-01 - a signed in user changing the own password: through the operation, the session stays the user's, paex reset
 *  PW-02 - a signed in user asking for another user's password form is refused, nothing is checked or changed
 *  PW-03 - nobody signed in (expired password): the user is signed in after the change, failed logins reset;
 *          a password that has not expired, or an account without password expiry, is refused
 *  PW-04 - RedirectOnChange and RedirectOnCancel reach redirectTo() only through returnURI()
 *  PW-05 - a wrong old password without a signed in user (expired password) counts as a failed login
 *  PW-06 - a disabled or locked account is neither changed nor signed in without a signed in user
 *  PW-07 - an operation that did not store the password (a workflow stopped it): no paex reset, no sign-in, no success
 *  PW-08 - the old password again is refused, also for a salted hash type
 *  PW-09 - a typed password is never written back into the page
 */

$failures = 0;
function pwCheck( $ok, $message )
{
    global $failures;
    echo ( $ok ? 'PASS' : 'FAIL' ), ": $message\n";
    if ( !$ok )
        $failures++;
}

class PwLog
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
}

class eZINI
{
    public static function instance( $name = 'site.ini' ) { return new self(); }
    public function variable( $group, $name ) { return $group === 'SiteSettings' && $name === 'DefaultPage' ? '/content/view/full/2' : false; }
    public function hasVariable( $group, $name ) { return false; }
}

class eZHTTPTool
{
    public static $post = array();
    public static function instance() { return new self(); }
    public function hasPostVariable( $name ) { return array_key_exists( $name, self::$post ); }
    public function postVariable( $name ) { return self::$post[$name]; }
    public function hasSessionVariable( $name, $force = true ) { return false; }
}

class eZUser
{
    const PASSWORD_HASH_PHP_DEFAULT = 7;
    /** @var eZUser[] */
    public static $users = array();
    public static $currentID = 10;
    public static $locked = array();
    public $data;

    public function __construct( $data ) { $this->data = $data; }
    public static function fetch( $id ) { return isset( self::$users[$id] ) ? clone self::$users[$id] : null; }
    public static function currentUser() { return self::$users[self::$currentID]; }
    public function attribute( $name ) { return $this->data[$name]; }
    public function setAttribute( $name, $value ) { PwLog::add( "setAttribute:$name" ); $this->data[$name] = $value; }
    public function store() { PwLog::add( 'store' ); }
    public function site() { return 'site'; }
    public function isRegistered() { return $this->data['contentobject_id'] != 10; }
    public function isLoggedIn() { return $this->isRegistered(); }
    public function isEnabled() { return $this->data['enabled']; }
    public function validatePassword( $password ) { return strlen( $password ) >= 3; }
    public static function isEnabledAfterFailedLogin( $id ) { return !in_array( (int)$id, self::$locked, true ); }
    // a salted hash type: two hashes of the same password differ, authenticate with password_verify()
    public static function createHash( $login, $password, $site, $type ) { return password_hash( $password, PASSWORD_DEFAULT ); }
    public static function authenticateHash( $login, $password, $site, $type, $hash ) { return password_verify( $password, $hash ); }
    public static function setCurrentlyLoggedInUser( $user, $id, $flags = 0 ) { PwLog::add( "signIn:$id" ); }
    public static function updateLastVisit( $id, $count = false ) { PwLog::add( "lastVisit:$id" ); }
    public static function setFailedLoginAttempts( $id, $value = false, $force = false ) { PwLog::add( 'failedLogin:' . $id . ':' . var_export( $value, true ) ); }
}

class eZUserOperationCollection
{
    public static $stop = false;
    public static function password( $id, $newPassword )
    {
        PwLog::add( "operation:$id" );
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

class eZRedirectManager
{
    public static function returnURI( $module, $default, $preferred = false, $options = array() )
    {
        foreach ( (array)$preferred as $uri )
        {
            PwLog::add( "returnURI:$uri" );
            if ( is_string( $uri ) && preg_match( '#^/(?!/)#', $uri ) )
                return $uri;
        }
        return $default;
    }
    public static function redirectTo( $module, $default ) { $module->redirectTo( $default ); return true; }
}

class eZError { const KERNEL_ACCESS_DENIED = 1; }

class eZAudit { public static function writeAudit( $name, $data ) { PwLog::add( "audit:$name" ); } }

class eZPaEx
{
    /** @var array user id => true (expired), false (not expired); missing: no paex datatype */
    public static $expired = array();
    public $id;
    public static function getPaEx( $id, $checkIfUserHasDatatype = false )
    {
        if ( $checkIfUserHasDatatype && !array_key_exists( (int)$id, self::$expired ) )
            return null;
        $paex = new self();
        $paex->id = (int)$id;
        return $paex;
    }
    public function isExpired() { return !empty( self::$expired[$this->id] ); }
    public function validatePassword( $password ) { return true; }
    public function resetPasswordLastUpdated() { PwLog::add( 'paexReset' ); }
}

class eZTemplate
{
    public static $vars = array();
    public static function factory() { return new self(); }
    public function setVariable( $name, $value ) { self::$vars[$name] = $value; }
    public function fetch( $template ) { return ''; }
}

class ezpI18n { public static function tr( $context, $text ) { return $text; } }

class PwModule
{
    public $redirect = null;
    public function redirectTo( $uri ) { $this->redirect = $uri; return 'redirected'; }
    public function setTitle( $title ) {}
    public function actionParameter( $name ) { return null; }
    public function handleError( $code, $type ) { PwLog::add( "error:$type:$code" ); return 'error'; }
}

function pwRun( $currentID, $userID, array $post )
{
    PwLog::$calls = array();
    eZTemplate::$vars = array();
    eZHTTPTool::$post = $post;
    eZUser::$currentID = $currentID;
    $module = new PwModule();
    $Params = array( 'Module' => $module, 'UserID' => $userID );
    $result = ( function() use ( $Params ) { return include dirname( __DIR__ ) . '/modules/userpaex/password.php'; } )();
    return array( $module, $result );
}

function pwReset()
{
    eZUser::$users = array(
        10 => new eZUser( array( 'contentobject_id' => 10, 'login' => 'anonymous', 'password_hash' => '', 'password_hash_type' => 7, 'enabled' => true ) ),
        14 => new eZUser( array( 'contentobject_id' => 14, 'login' => 'operator', 'password_hash' => password_hash( 'op-secret', PASSWORD_DEFAULT ), 'password_hash_type' => 7, 'enabled' => true ) ),
        42 => new eZUser( array( 'contentobject_id' => 42, 'login' => 'jane', 'password_hash' => password_hash( 'old-secret', PASSWORD_DEFAULT ), 'password_hash_type' => 7, 'enabled' => true ) ),
    );
    eZUser::$locked = array();
    eZUserOperationCollection::$stop = false;
    eZPaEx::$expired = array( 42 => true );
}

$change = array( 'OKButton' => '1', 'oldPassword' => 'old-secret', 'newPassword' => 'new-secret', 'confirmPassword' => 'new-secret' );

// PW-01
pwReset();
list( $module ) = pwRun( 42, 42, $change );
pwCheck( PwLog::has( 'operation:42' ) && !PwLog::has( 'setAttribute:password_hash' ) && PwLog::has( 'paexReset' )
         && PwLog::has( 'signIn:42' ) && !PwLog::has( 'failedLogin' ) && $module->redirect === '/content/view/full/2',
         'PW-01 own password: operation, paex reset, session stays the user\'s (' . implode( ' ', PwLog::$calls ) . ')' );

// PW-02
pwReset();
list( $module, $result ) = pwRun( 14, 42, $change );
pwCheck( $result === 'error' && PwLog::has( 'error:kernel:1' ) && !PwLog::has( 'operation:' ) && !PwLog::has( 'audit:' )
         && !PwLog::has( 'signIn:' ) && !PwLog::has( 'failedLogin' ),
         'PW-02 another user\'s password form: refused before the old password is checked (' . implode( ' ', PwLog::$calls ) . ')' );
pwReset();
list( $module, $result ) = pwRun( 14, 42, array() );
pwCheck( $result === 'error' && PwLog::has( 'error:kernel:1' ), 'PW-02 another user\'s password form is not shown either' );

// PW-03
pwReset();
list( $module ) = pwRun( 10, 42, $change );
pwCheck( PwLog::has( 'operation:42' ) && PwLog::has( 'signIn:42' ) && PwLog::has( 'failedLogin:42:0' ),
         'PW-03 expired password, nobody signed in: signed in after the change, failed logins reset' );
pwReset();
eZPaEx::$expired = array( 42 => false );
list( $module, $result ) = pwRun( 10, 42, $change );
pwCheck( $result === 'error' && PwLog::has( 'error:kernel:1' ) && !PwLog::has( 'operation:' ) && !PwLog::has( 'signIn:' ) && !PwLog::has( 'failedLogin' ),
         'PW-03 password not expired, nobody signed in: refused, no sign-in' );
pwReset();
eZPaEx::$expired = array();
list( $module, $result ) = pwRun( 10, 42, $change );
pwCheck( $result === 'error' && !PwLog::has( 'operation:' ) && !PwLog::has( 'signIn:' ),
         'PW-03 account without password expiry, nobody signed in: refused, no sign-in' );
pwReset();
eZPaEx::$expired = array( 42 => false );
list( $module, $result ) = pwRun( 42, 42, $change );
pwCheck( PwLog::has( 'operation:42' ) && PwLog::has( 'paexReset' ), 'PW-03 a signed in user changes the own password whether it expired or not' );

// PW-04
pwReset();
list( $module ) = pwRun( 42, 42, $change + array( 'RedirectOnChange' => 'https://elsewhere.example/' ) );
pwCheck( PwLog::has( 'returnURI:https://elsewhere.example/' ) && $module->redirect === '/content/view/full/2',
         'PW-04 RedirectOnChange to another host goes through returnURI() and is refused' );
pwReset();
list( $module ) = pwRun( 42, 42, $change + array( 'RedirectOnChange' => '/content/view/full/77' ) );
pwCheck( $module->redirect === '/content/view/full/77', 'PW-04 RedirectOnChange inside the site is followed' );
pwReset();
list( $module ) = pwRun( 42, 42, array( 'CancelButton' => '1', 'RedirectOnCancel' => '//elsewhere.example/' ) );
pwCheck( PwLog::has( 'returnURI://elsewhere.example/' ) && $module->redirect === '/content/view/full/2' && !PwLog::has( 'operation:' ),
         'PW-04 RedirectOnCancel to another host goes through returnURI() and is refused' );

// PW-05
pwReset();
pwRun( 10, 42, array( 'oldPassword' => 'wrong' ) + $change );
pwCheck( PwLog::has( 'failedLogin:42:false' ) && !PwLog::has( 'operation:' ) && !PwLog::has( 'signIn:' ),
         'PW-05 wrong old password without a signed in user counts as a failed login' );
pwReset();
pwRun( 42, 42, array( 'oldPassword' => 'wrong' ) + $change );
pwCheck( !PwLog::has( 'failedLogin' ), 'PW-05 wrong old password of the signed in user is not a failed login' );

// PW-06
pwReset();
eZUser::$locked = array( 42 );
list( $module, $result ) = pwRun( 10, 42, $change );
pwCheck( $result === 'error' && !PwLog::has( 'operation:' ) && !PwLog::has( 'signIn:' ),
         'PW-06 locked account: refused, not changed, not signed in' );
pwReset();
eZUser::$users[42]->data['enabled'] = false;
pwRun( 10, 42, $change );
pwCheck( !PwLog::has( 'operation:' ) && !PwLog::has( 'signIn:' ), 'PW-06 disabled account: not changed, not signed in' );

// PW-07
pwReset();
eZUserOperationCollection::$stop = true;
list( $module, $result ) = pwRun( 42, 42, $change );
pwCheck( PwLog::has( 'operation:42' ) && !PwLog::has( 'paexReset' ) && !PwLog::has( 'signIn:' ) && $module->redirect === null
         && eZTemplate::$vars['message'] === 0,
         'PW-07 password not stored: no paex reset, no sign-in, no success message' );

// PW-08
pwReset();
pwRun( 42, 42, array( 'newPassword' => 'old-secret', 'confirmPassword' => 'old-secret' ) + $change );
pwCheck( !PwLog::has( 'operation:' ) && eZTemplate::$vars['newPasswordMustDiffer'] === 1, 'PW-08 the old password again is refused' );

// PW-09
pwReset();
pwRun( 42, 42, array( 'newPassword' => 'x', 'confirmPassword' => 'x' ) + $change );
pwCheck( eZTemplate::$vars['oldPassword'] === '' && eZTemplate::$vars['newPassword'] === '' && eZTemplate::$vars['confirmPassword'] === ''
         && eZTemplate::$vars['newPasswordNotValidate'] === 1,
         'PW-09 a typed password is never written back into the page' );

echo $failures ? "FAIL: $failures\n" : "PASS: all\n";
exit( $failures ? 1 : 0 );
