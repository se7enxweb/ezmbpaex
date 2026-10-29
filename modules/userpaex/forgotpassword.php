<?php
/**
 * File containing the forgotpassword view
 *
 * @copyright Copyright (C) 1998 - 2026 Exponential Foundation and 7x. All rights reserved.
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 * @package ezmbpaex
 */

$tpl = eZTemplate::factory();
$tpl->setVariable( 'generated', false );
$tpl->setVariable( 'wrong_email', false );
$tpl->setVariable( 'link', false );
$tpl->setVariable( 'wrong_key', false );
$tpl->setVariable( 'password_form', false );
$tpl->setVariable( 'newPasswordNotValidate', false );
$tpl->setVariable( 'newPasswordMustDiffer', false );
$tpl->setVariable( 'password_changed', false );
$tpl->setVariable( 'newPasswordNotMatch', false );

$http = eZHTTPTool::instance();
$module = $Params["Module"];
// No key in the address (the plain form) arrives as null: treat it as an empty key
$hashKey = (string)( $Params["HashKey"] ?? '' );
$hashKeyValidated = false;
$mbpaex_ini = eZINI::instance('mbpaex.ini');
$forgotPasswdHashLifeTime = $mbpaex_ini->variable( "mbpaexSettings", "ForgotPasswordHashLifeTime" );
$ini = eZINI::instance();

if ( strlen( $hashKey ) == 32 )
{
    $currentTime = time();

    $forgotPasswdObj = eZForgotPassword::fetchByKey( $hashKey );
    if (!is_object($forgotPasswdObj)) // HashKey not found
    {
        // if audit is enabled password changes should be logged
        eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'HashKey' => $hashKey,
                                                                'Comment' => 'HashKey not found' ) );

        $tpl->setVariable( 'wrong_key', true );
    }
    elseif (($currentTime - $forgotPasswdObj->attribute('time')) > $forgotPasswdHashLifeTime) // HashKey expired
    {
        // if audit is enabled password changes should be logged
        eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'HashKey' => $hashKey,
                                                                'Comment' => 'HashKey expired, proceed to remove' ) );

        $forgotPasswdObj->remove(); // Remove expired hash
        $tpl->setVariable( 'wrong_key', true );
    }
    elseif ( !eZUser::fetch( $forgotPasswdObj->attribute( 'user_id' ) ) instanceof eZUser ) // the account is gone
    {
        // if audit is enabled password changes should be logged
        eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'HashKey' => $hashKey,
                                                                'Comment' => 'User of the HashKey not found, proceed to remove' ) );

        $forgotPasswdObj->remove();
        $tpl->setVariable( 'wrong_key', true );
    }
    elseif ( class_exists( 'expDemoMode' ) && method_exists( 'expDemoMode', 'protectsPassword' )
             && expDemoMode::protectsPassword( eZUser::fetch( $forgotPasswdObj->attribute( 'user_id' ) ) ) )
    {
        // Demo mode of the kernel: an administrator's password cannot be reset. The key (made before the mode was
        // switched on) is removed and refused, as in the kernel's user/forgotpassword; the user/password operation
        // would refuse the change anyway
        if ( method_exists( 'expDemoMode', 'refused' ) )
            expDemoMode::refused( (int)$forgotPasswdObj->attribute( 'user_id' ), 'userpaex/forgotpassword', 'access.user.password.reset.failed' );

        $forgotPasswdObj->remove();
        $tpl->setVariable( 'wrong_key', true );
    }
    else // HashKey OK -> show/process change password form
    {
        $tpl->setVariable( 'password_form', true );
        $tpl->setVariable( 'HashKey', $hashKey );
        $hashKeyValidated = true;
    }
}
else if ( strlen( $hashKey ) > 4 )
{
    // if audit is enabled password changes should be logged
    eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'HashKey' => $hashKey,
                                                            'Comment' => 'HashKey not found' ) );

    $tpl->setVariable( 'wrong_key', true );
}

if ( $module->isCurrentAction( "Generate" ) )
{
    $passwordLength = $ini->variable( "UserSettings", "GeneratePasswordLength" );
    $password = eZUser::createPassword( $passwordLength );
    $passwordConfirm = $password;

    if ( $module->hasActionParameter( "Email" ) )
    {
        $email = $module->actionParameter( "Email" );
        // A form can post the address as an array; treat that as not given
        if ( !is_string( $email ) ) $email = "";
        $users = array();
        if ( trim( $email ) != "" && eZMail::validate( $email ) )
        {
            $users = eZPersistentObject::fetchObjectList( eZUser::definition(),
                                                       null,
                                                       array( 'email' => $email ),
                                                       null,
                                                       null,
                                                       true );
        }
        if ( !empty( $users ) )
        {
            $user = $users[0];
            $time = time();
            // The key is all that stands between a reset link and the account: 128 random bits from the
            // system's secure source, 32 hex characters like the md5 it replaces (mt_rand() and the time
            // could be guessed)
            $hashKey = bin2hex( random_bytes( 16 ) );

            $db = eZDB::instance();
            $db->begin();

            // Remove previous generated hash keys for same user
            eZForgotPassword::removeByUserID($user->id());

            $forgotPasswdObj = eZForgotPassword::createNew( $user->id(), $hashKey, $time );
            $forgotPasswdObj->store();

            $userToSendEmail = $user;
            $receiver = $email;

            $mail = new eZMail();
            if ( !$mail->validate( $receiver ) )
            {
            }
            $tpl = eZTemplate::factory();
            $tpl->setVariable( 'user', $userToSendEmail );
            $tpl->setVariable( 'object', $userToSendEmail->attribute( 'contentobject' ) );
            $tpl->setVariable( 'password', $password );
            $tpl->setVariable( 'link', true );
            $tpl->setVariable( 'hash_key', $hashKey );
            $tpl->setVariable( 'hash_key_lifetime', date("d/m/Y H:i",time() + $forgotPasswdHashLifeTime));

            $http = eZHTTPTool::instance();
            $http->UseFullUrl = true;
            $templateResult = $tpl->fetch( 'design:userpaex/forgotpasswordmail.tpl' );
            $http->UseFullUrl = false;
            $emailSender = $ini->variable( 'MailSettings', 'EmailSender' );
            if ( !$emailSender )
                $emailSender = $ini->variable( 'MailSettings', 'AdminEmail' );
            $mail->setSender( $emailSender );
            $mail->setReceiver( $receiver );
            $subject = ezpI18n::tr( 'kernel/user/register', 'Registration info' );
            if ( $tpl->hasVariable( 'subject' ) )
                $subject = $tpl->variable( 'subject' );
            $mail->setSubject( $subject );
            $mail->setBody( $templateResult );
            $mailResult = eZMailTransport::send( $mail );
            $tpl->setVariable( 'email', $email );
            $db->commit();

            // if audit is enabled password changes should be logged
            eZAudit::writeAudit( 'user-forgotpassword', array( 'Email' => $email,
                                                               'Comment' => 'Forgotpassword email sent' ) );

        }
        else if ( trim( $email ) !== '' && eZMail::validate( trim( $email ) )
                  && !preg_match( '/[<>"\'&\\\\]/', $email ) )
        {
            // if audit is enabled password changes should be logged
            eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'Email' => $email,
                                                                    'Comment' => 'Email address not found' ) );

            // No user has this address. Answer exactly as for one that
            // does, so the form cannot be used to find out which addresses
            // have an account. The address is echoed by the page, and older
            // designs print it unescaped, so only a plain address (no quoted
            // local part, nothing HTML could read as markup) gets this far.
            $tpl->setVariable( 'link', true );
            $tpl->setVariable( 'email', $email );
        }
        else
        {
            // Not an email address at all: saying so reveals nothing.
            $tpl->setVariable( 'wrong_email', $email );
        }
    }
}
else if ( $module->isCurrentAction( "ChangePassword" ) && $hashKeyValidated )
{
    if ( $module->hasActionParameter( "NewPassword" ) )
        $newPassword = $module->actionParameter( "NewPassword" );
    else
        $newPassword = false;

    if ( $module->hasActionParameter( "NewPasswordConfirm" ) )
        $confirmPassword = $module->actionParameter( "NewPasswordConfirm" );
    else
        $confirmPassword = false;

    // A form can post these as arrays; treat that as not given
    if ( !is_string( $newPassword ) ) $newPassword = '';
    if ( !is_string( $confirmPassword ) ) $confirmPassword = '';

    // The forgotPasswdObj was previously validated, fetch the corresponding user object
    $UserID = $forgotPasswdObj->attribute( 'user_id' );
    $user = eZUser::fetch($UserID);
    $login = $user->attribute( "login" );
    $type = $user->attribute( "password_hash_type" );
    $hash = $user->attribute( "password_hash" );
    $site = $user->site();

    // strict: with == two different numeric strings ("1e3", "1000") would count as the same password
    if (  $newPassword === $confirmPassword )
    {
        if ( !$user->validatePassword($newPassword) ) // Password must meet "old" validation rules
        {
            // if audit is enabled password changes should be logged
            eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'UserID' => $UserID, 'Login' => $login,
                                                                    'Comment: ' => 'Password not pass standard validation' ) );

            $tpl->setVariable( 'newPasswordNotValidate', true);
        }
        else
        {
            // Patch for use mbpaex::validatePassword
            $paex = eZPaEx::getPaEx($UserID);
            if (!$paex->validatePassword($newPassword))
            {
                // if audit is enabled password changes should be logged
                eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'UserID' => $UserID, 'Login' => $login,
                                                                        'Comment: ' => 'Password not pass PAEX validation' ) );

                $tpl->setVariable( 'newPasswordNotValidate', true);
            }
            // The new password is the old one when it matches the stored hash (comparing a new hash with the
            // stored one fails for salted hash types)
            else if ( $user->authenticateHash( $login, $newPassword, $site, $type, $hash ) )
            {
                // if audit is enabled password changes should be logged
                eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'UserID' => $UserID, 'Login' => $login,
                                                                        'Comment: ' => 'New and old password are the same' ) );

                $tpl->setVariable( 'newPasswordMustDiffer', true);
            }
            else
            {
                // Through the kernel's user/password operation, as user/password does: the current hash type,
                // the user draft, the content cache and the workflows of the operation
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
                    eZAudit::writeAudit( 'user-forgotpassword', array( 'UserID' => $UserID, 'Login' => $login,
                                                                       'Comment: ' => 'Password changed successfully' ) );

                    // the key works once: removed first, so nothing that fails below leaves it usable
                    $forgotPasswdObj->remove();

                    $paex->resetPasswordLastUpdated();

                    // What the kernel does after a password change, where it can: end the user's sessions (this
                    // request is not one of them, nobody is signed in by this view), tell the user by mail, clear
                    // "change password at next sign-in"
                    if ( class_exists( 'expPasswordPolicy' ) && method_exists( 'expPasswordPolicy', 'endOtherSessions' ) )
                    {
                        $policy = new expPasswordPolicy( $ini );
                        $sessionsEnded = $policy->endOtherSessions( (int)$UserID );
                        if ( method_exists( $policy, 'sendChangedMail' ) )
                            $policy->sendChangedMail( $stored, $sessionsEnded,
                                                      method_exists( 'expPasswordPolicy', 'stampCheckEnabled' ) && expPasswordPolicy::stampCheckEnabled() );
                    }
                    if ( class_exists( 'expPasswordChangeRequired' ) && method_exists( 'expPasswordChangeRequired', 'clear' ) )
                        expPasswordChangeRequired::clear( $stored, 'forgotpassword' );

                    $tpl->setVariable( 'password_changed', true);
                }
                else
                {
                    // the key stays, the form is shown again; no flag names this failure, so no message rather
                    // than "changed successfully"
                    eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'UserID' => $UserID, 'Login' => $login,
                                                                            'Comment: ' => 'Password could not be stored' ) );
                }
            }
        }
    }
    else
    {
        // if audit is enabled password changes should be logged
        eZAudit::writeAudit( 'user-forgotpassword-fail', array( 'UserID' => $UserID, 'Login' => $login,
                                                                'Comment: ' => 'Password not match password confirmation' ) );

        $tpl->setVariable( 'newPasswordNotMatch', true);
    }
}

$Result = array();
$Result['content'] = $tpl->fetch( 'design:userpaex/forgotpassword.tpl' );
$Result['path'] = array( array( 'text' => ezpI18n::tr( 'kernel/user', 'User' ),
                                'url' => false ),
                         array( 'text' => ezpI18n::tr( 'kernel/user', 'Forgot password' ),
                                'url' => false ) );

if ( $ini->variable( 'SiteSettings', 'LoginPage' ) == 'custom' )
{
    $Result['pagelayout'] = 'loginpagelayout.tpl';
}

?>
