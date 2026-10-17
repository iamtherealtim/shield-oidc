<?php

declare(strict_types=1);

// Messages people see. Copy to app/Language/<locale>/Oidc.php to translate or reword.
return [
    'signInWith'          => 'Sign in with {0}',
    'unknownProvider'     => 'That sign-in option isn\'t available.',
    'providerUnavailable' => 'Single sign-on isn\'t working right now. Please try again later or use another way to sign in.',
    'providerError'       => 'The sign-in provider reported a problem. Please try again.',
    'accessDenied'        => 'Sign-in was cancelled, or your account isn\'t allowed to use this app.',
    'stateInvalid'        => 'This sign-in link isn\'t valid any more. Please start again.',
    'stateExpired'        => 'Sign-in took too long. Please start again.',
    'tokenInvalid'        => 'We couldn\'t verify your sign-in. Please try again.',
    'noAccount'           => 'There\'s no account for you here yet. Ask an administrator for access.',
    'emailTaken'          => 'An account with your email address already exists. Sign in to it the usual way, then connect {0} from your account.',
    'domainNotAllowed'    => 'Accounts from your organization can\'t sign in here.',
    'registerFailed'      => 'Your account couldn\'t be created. Please contact an administrator.',
    'alreadyLinked'       => 'That {0} account is already connected to a different user.',
    'linkNeedsLogin'      => 'Sign in first, then connect your account.',
    'linked'              => 'Your {0} account is now connected.',
    'connect'             => 'Connect {0}',
    'notActivated'        => 'Your account hasn\'t been activated yet.',
    'loginBlocked'        => 'Your account needs another step before you can sign in. Please contact an administrator.',
];
