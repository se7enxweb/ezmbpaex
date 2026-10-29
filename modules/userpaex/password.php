<?php
/**
 * File containing the password view
 *
 * @copyright Copyright (C) 1998 - 2026 Exponential Foundation and 7x. All rights reserved.
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 * @package ezmbpaex
 */

$ini = eZINI::instance();
$currentUser = eZUser::currentUser();
$currentUserID = $currentUser->attribute( "contentobject_id" );
$http = eZHTTPTool::instance();
$Module = $Params["Module"];
$message = 0;
$oldPasswordNotValid = 0;
$newPasswordNotMatch = 0;
$newPasswordTooShort = 0;
$newPasswordNotValidate = 0;
$newPasswordMustDiffer = 0;

// Where the view goes after a change or a cancel: the page the form names, else the page viewed
// before the form, else the default page. A posted page is only taken when it passes the rules of
// eZRedirectManager::returnURI() (no other host, no script URL, not this form again); a kernel
// without returnURI() ignores the posted page.
$defaultURI = $ini->variable( 'SiteSettings', 'DefaultPage' );
$redirectBack = function( array $postNames ) use ( $Module, $http, $defaultURI )
{
    if ( method_exists( 'eZRedirectManager', 'returnURI' ) )
    {
        $preferred = array();
        foreach ( $postNames as $name )
        {
            $value = $http->hasPostVariable( $name ) ? $http->postVariable( $name ) : null;
            if ( is_string( $value ) && trim( $value ) !== '' )
                $preferred[] = trim( $value );
        }
        return $Module->redirectTo( eZRedirectManager::returnURI( $Module, $defaultURI, $preferred ) );
    }
    eZRedirectManager::redirectTo( $Module, $defaultURI );
    return null;
};

if( !isset( $oldPassword ) )
    $oldPassword = '';

if( !isset( $newPassword ) )
    $newPassword = '';

if( !isset( $confirmPassword ) )
    $confirmPassword = '';

if ( is_numeric( $Params["UserID"] ) )
    $UserID = $Params["UserID"];
else
    $UserID = false;

$user = eZUser::fetch( $UserID );

// A signed in user changes the own password only, as in the kernel's user/password view.
if ( $user && $currentUser->isRegistered() && $currentUserID != $user->attribute( "contentobject_id" ) )
    return $Module->handleError( eZError::KERNEL_ACCESS_DENIED, 'kernel' );

// Without a signed in user the form is the way in for a user whose password expired (the login handler
// sends that user here instead of signing in), and it signs the user in after the change. Only for an
// expired password of an account that may sign in; it is no way around the login form for other accounts.
$signsIn = $user && !$currentUser->isRegistered();
if ( $signsIn )
{
    $expiryPaex = eZPaEx::getPaEx( $UserID, true );
    if ( !$expiryPaex instanceof eZPaEx || !$expiryPaex->isExpired()
         || !$user->isEnabled() || !eZUser::isEnabledAfterFailedLogin( $UserID ) )
        return $Module->handleError( eZError::KERNEL_ACCESS_DENIED, 'kernel' );
}

if ( $http->hasPostVariable( "OKButton" ) && $user )
{
    if ( $http->hasPostVariable( "oldPassword" ) )
    {
        $oldPassword = $http->postVariable( "oldPassword" );
    }
    if ( $http->hasPostVariable( "newPassword" ) )
    {
        $newPassword = $http->postVariable( "newPassword" );
    }
    if ( $http->hasPostVariable( "confirmPassword" ) )
    {
        $confirmPassword = $http->postVariable( "confirmPassword" );
    }
    if ( !is_string( $oldPassword ) ) $oldPassword = '';
    if ( !is_string( $newPassword ) ) $newPassword = '';
    if ( !is_string( $confirmPassword ) ) $confirmPassword = '';

    $login = $user->attribute( "login" );
    $type = $user->attribute( "password_hash_type" );
    $hash = $user->attribute( "password_hash" );
    $site = $user->site();

    if ( $user->authenticateHash( $login, $oldPassword, $site, $type, $hash ) ) // Old password is correct
    {
        if (  $newPassword == $confirmPassword )
        {
            if ( !$user->validatePassword($newPassword) )
            {
                // if audit is enabled password changes should be logged
                eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                              'Comment: ' => 'Password not pass standard validation' ) );

                $newPasswordNotValidate = 1;
            }
            else
            {
                // Patch for use mbpaex::validatePassword
                $paex = eZPaEx::getPaEx( $UserID );
                if (!$paex->validatePassword($newPassword))
                {
                    // if audit is enabled password changes should be logged
                    eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                                  'Comment: ' => 'Password not pass PAEX validation' ) );
                    $newPasswordNotValidate = 1;
                }
                // The new password is the old one when it matches the stored hash (comparing two new hashes
                // fails for salted hash types)
                else if ( $user->authenticateHash( $login, $newPassword, $site, $type, $hash ) )
                {
                    // if audit is enabled password changes should be logged
                    eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                                  'Comment: ' => 'New and old password are the same' ) );
                    $newPasswordMustDiffer = 1;
                }
                else
                {
                    // Through the kernel's user/password operation, as user/password does: the current hash
                    // type, the user draft, the content cache and the workflows of the operation
                    if ( eZOperationHandler::operationIsAvailable( 'user_password' ) )
                    {
                        eZOperationHandler::execute( 'user', 'password', array( 'user_id' => $UserID,
                                                                                'new_password' => $newPassword ) );
                    }
                    else
                    {
                        eZUserOperationCollection::password( $UserID, $newPassword );
                    }

                    // the stored hash says whether it went through (a workflow can stop the operation)
                    $stored = eZUser::fetch( $UserID );
                    if ( $stored instanceof eZUser
                         && $stored->authenticateHash( $login, $newPassword, $stored->site(),
                                                       $stored->attribute( "password_hash_type" ),
                                                       $stored->attribute( "password_hash" ) ) )
                    {
                        // if audit is enabled password changes should be logged
                        eZAudit::writeAudit( 'user-password-change-self', array( 'UserID: ' => $UserID, 'Login: ' => $login ) );

                        $paex->resetPasswordLastUpdated();

                        // the session is the user's own (see above): signed in with the new password
                        eZUser::setCurrentlyLoggedInUser( $stored, $UserID );
                        eZUser::updateLastVisit( $UserID, true );
                        // a sign-in that succeeds starts the count of failed logins again
                        if ( $signsIn )
                            eZUser::setFailedLoginAttempts( $UserID, 0 );

                        // What the kernel does after a password change, where it can: end the user's other
                        // sessions, tell the user by mail, clear "change password at next sign-in"
                        if ( class_exists( 'expPasswordPolicy' ) && method_exists( 'expPasswordPolicy', 'endOtherSessions' ) )
                        {
                            $policy = new expPasswordPolicy( $ini );
                            $sessionsEnded = $policy->endOtherSessions( (int)$UserID );
                            if ( method_exists( $policy, 'sendChangedMail' ) )
                                $policy->sendChangedMail( $stored, $sessionsEnded,
                                                          method_exists( 'expPasswordPolicy', 'stampCheckEnabled' ) && expPasswordPolicy::stampCheckEnabled() );
                        }
                        if ( class_exists( 'expPasswordChangeRequired' ) && method_exists( 'expPasswordChangeRequired', 'clear' ) )
                            expPasswordChangeRequired::clear( $stored, 'password' );

                        return $redirectBack( array( 'RedirectOnChange' ) );
                    }

                    eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                                  'Comment: ' => 'Password could not be stored' ) );
                    // no flag names this failure: show no message rather than "successfully updated"
                    $message = 0;
                }
            }
            if ( $newPasswordNotValidate || $newPasswordMustDiffer )
            {
                $newPassword = '';
                $confirmPassword = '';
                $message = true;
            }
        }
        else
        {
            // if audit is enabled password changes should be logged
            eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                          'Comment: ' => 'Password not match password confirmation' ) );
            $newPassword = "";
            $confirmPassword = "";
            $newPasswordNotMatch = 1;
            $message = true;
        }
    }
    else
    {
        // if audit is enabled password changes should be logged
        eZAudit::writeAudit( 'user-password-change-self-fail', array( 'UserID: ' => $UserID, 'Login: ' => $login,
                                                                      'Comment: ' => 'Old password incorrect' ) );
        // Without a signed in user this form is a sign-in: a wrong password counts as a failed login
        if ( $signsIn )
            eZUser::setFailedLoginAttempts( $UserID );
        $oldPassword = "";
        $oldPasswordNotValid = 1;
        $message = true;
    }
}

if ( $http->hasPostVariable( "CancelButton" ) || !$user )
{
    return $redirectBack( array( 'RedirectOnCancel' ) );
}

// a typed password is never written back into the page
$oldPassword = '';
$newPassword = '';
$confirmPassword = '';

$Module->setTitle( "Edit user information" );
// Template handling
$tpl = eZTemplate::factory();
$tpl->setVariable( "module", $Module );
$tpl->setVariable( "http", $http );
$tpl->setVariable( "userID", $UserID );
$tpl->setVariable( "userAccount", $user );
$tpl->setVariable( "oldPassword", $oldPassword );
$tpl->setVariable( "newPassword", $newPassword );
$tpl->setVariable( "confirmPassword", $confirmPassword );
$tpl->setVariable( "oldPasswordNotValid", $oldPasswordNotValid );
$tpl->setVariable( "newPasswordNotMatch", $newPasswordNotMatch );
$tpl->setVariable( "newPasswordTooShort", $newPasswordTooShort );
$tpl->setVariable( "newPasswordNotValidate", $newPasswordNotValidate );
$tpl->setVariable( "newPasswordMustDiffer", $newPasswordMustDiffer );
$tpl->setVariable( "message", $message );

$Result = array();
$Result['path'] = array( array( 'text' => ezpI18n::tr( 'kernel/user', 'User' ),
                                'url' => false ),
                         array( 'text' => ezpI18n::tr( 'kernel/user', 'Change password' ),
                                'url' => false ) );
$Result['content'] = $tpl->fetch( "design:userpaex/password.tpl" );

$currentuser = eZUser::currentUser();
if ( !$currentuser->isLoggedIn() )
{
   if ( $ini->variable( 'SiteSettings', 'LoginPage' ) == 'custom' )
   {
       $Result['pagelayout'] = 'loginpagelayout.tpl';
   }
}
?>
