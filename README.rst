ReCaptchaV3
==============

Usage
--------

Setup your settings.py, and that's all, you can also use the permission in the desired view instead of globally

.. code:: python

    GOOGLE_RECAPTCHA_IGNORE=False
    GOOGLE_RECAPTCHA_SECRET="mysecret"
    
    REST_FRAMEWORK = {
        "DEFAULT_PERMISSION_APPS": recaptchav3.permissions.IsNotARobot
    }

