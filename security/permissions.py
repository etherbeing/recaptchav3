"""
Implementation of Google permission related APIs, for example is not a robot
"""

import json
from typing import Any, cast

from django.conf import settings
from django.utils.timezone import datetime, timedelta
from requests import Response, post
from rest_framework.permissions import BasePermission
from rest_framework.request import Request


class GoogleReCAPTCHAv3:
    """
    Manages Google ReCaptcha v3 integration, calls the API and expose the resuls for each requests as a normal python dictionary object
    """

    GOOGLE_RECAPTCHA_V3 = "https://www.google.com/recaptcha/api/siteverify"
    TIME_UMBRAL = timedelta(minutes=5)  # 5 minutes of time offset
    SCORE_MIN = 0.8

    class Response:
        """Use this class to wrap up and use the Google responses in a python like way"""

        def __init__(self, res: Response) -> None:
            """Constructor (initializer) receives a response object, one that should contain the json method in it to obtain the necessary information"""
            data = res.json()
            (
                self.success,
                self.challenge_ts,
                self.hostname,
                self.error_codes,
                self.score,
            ) = (
                data.get("success", False),
                datetime.fromisoformat(data.get("challenge_ts")),
                data.get("hostname", None),
                data.get("error_codes", []),
                data.get("score", 0),
            )

        def to_dict(self) -> dict[str, Any]:
            """Allows you to parse this Response class as a dict object"""
            return {
                "success": self.success,
                # timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
                "challenge_ts": self.challenge_ts,
                # the hostname of the site where the reCAPTCHA was solved
                "hostname": self.hostname,
                "error-codes": self.error_codes,  # optional
            }

        def validate_success(self):
            """Test the success variable there is a typo here that need to be solved."""
            return self.success

        def validate_sucess(self):
            """Test the success variable there is a typo here that need to be solved."""
            return self.validate_success()

        def validate_ts(self):
            """Validate Timestamp, to avoid validating old challenges"""
            return (
                datetime.now(self.challenge_ts.tzinfo) - self.challenge_ts
                < GoogleReCAPTCHAv3.TIME_UMBRAL
            )

        def validate_hostname(self):
            """Validate the given hostname is in the ALLOWED_HOSTS, like a way for protection against tampering"""
            return self.hostname in settings.ALLOWED_HOSTS

        def validate_score(
            self,
        ):
            """Validate the score given by google to determine whether the user is a Robot or not"""
            return self.score > GoogleReCAPTCHAv3.SCORE_MIN

        def is_ok(
            self,
        ):
            """Run all validations and returns whether they all pass or not"""
            return (
                self.validate_sucess()
                and self.validate_ts()
                and self.validate_hostname()
                and self.validate_score()
            )

    def __init__(self, data: dict[str, Any]) -> None:
        """Convert a request's data json into a class that can be verified"""
        self.response = data.get("retoken")

    def verify(
        self,
    ) -> bool:
        """Runs the verification against the google Rest API"""
        return (
            settings.GOOGLE_RECAPTCHA_IGNORE
            or self.Response(
                post(
                    self.GOOGLE_RECAPTCHA_V3,
                    timeout=60,
                    params={
                        "secret": settings.GOOGLE_RECAPTCHA_SECRET,
                        "response": self.response,
                        "remoteip": "127.0.0.1",
                    },
                )
            ).is_ok()
        )


"""
## Permission
Handle whether a request should or should have permission to access a viewset by using the default Rest Framework permission API.

"""


class IsNotARobot(BasePermission):
    """
    Manages permission for users that are proven to be not a robot, meaning that after we add this permission to your own viewset or view
    just users that are proven to not be a robot will reach your view's actual code.
    ### Usage
    ```python
        from rest_framework.viewsets import GenericViewSet

        class MyViewSet(GenericViewSet):
            permission_classes = (IsNotARobot,)
            ...
    ```
    """

    def has_permission(self, request: Request, view=None) -> bool:  # type: ignore
        """
        This module is overrided in order to actually verify if the request has or not the necessary permissions

        :request: The rest_framework request containing the necessary data in its body needed for validations.

        :type HttpRequest:

        :param view: This parameter is not used actually therefore we wont document it

        :type None:

        :return: It returns True if is not a robot or we are in debug mode or false otherwise

        :rtype bool:

        """
        try:
            if request.data:
                return GoogleReCAPTCHAv3(cast(dict[str, Any], request.data)).verify()
        except json.JSONDecodeError:
            pass
        return settings.DEBUG

