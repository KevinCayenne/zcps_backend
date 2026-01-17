import logging
from django.conf import settings
import uuid
import requests


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def send_sms(phone_number, message):
    sns_resource = settings.SNS_RESOURCE

    if not sns_resource:
        return {"status": "error", "message": "SNS resource not found."}

    try:
        # Define the request URL for single SMS (not bulk)
        req_url = "https://smsapi.mitake.com.tw/api/mtk/SmSend?CharsetURL=UTF-8"
        # Define the POST parameters
        params = {
            "username": settings.MITAKE_USERNAME,
            "password": settings.MITAKE_PASSWORD,
            "dstaddr": phone_number,
            "smbody": message,
        }
        # Set the headers
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        # Send the POST request
        response = requests.post(req_url, data=params, headers=headers)

        # Check for the status code and response content for statuscode 0
        if response.status_code == 200 and any(
            f"statuscode={i}" in response.text for i in range(5)
        ):
            return {"status": "success", "message": "簡訊發送成功!"}
        else:
            return {
                "status": "error",
                "message": f"簡訊發送時出現問題: {response.text}",
            }
    except Exception as e:
        return {"status": "error", "message": f"Failed to send SMS: {str(e)}"}


def send_sms_bulk_by_mitake(sms_data_list: list) -> list[tuple[bool, str]]:
    url = settings.MITAKE_BULK_URL
    params = {
        "username": settings.MITAKE_USERNAME,
        "password": settings.MITAKE_PASSWORD,
        "Encoding_PostIn": "UTF-8",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    results: list[tuple[bool, str]] = []
    for i in range(0, len(sms_data_list), settings.MITAKE_BULK_MAX):
        data = sms_data_list[i : i + settings.MITAKE_BULK_MAX]
        body = "\n".join(
            f"{str(uuid.uuid4())}$${sms_data.phone}$${sms_data.dlvTime}$${sms_data.vldTime}$$"
            f"{sms_data.receiverName}$${sms_data.response}$${sms_data.smBody}"
            for sms_data in data
        )
        try:
            resp = requests.post(
                url, headers=headers, params=params, data=body.encode()
            )
            if resp.status_code == 200 and any(
                f"statuscode={i}" in resp.text for i in range(5)
            ):
                results.append((True, f"簡訊發送成功! {resp.text}"))
            else:
                logger.error(f"簡訊發送時出現問題: {resp.text}")
                results.append((False, f"簡訊發送時出現問題: {resp.text}"))
        except Exception as e:
            logger.error(f"Failed to send SMS: {str(e)}")
            results.append((False, f"Failed to send SMS: {str(e)}"))

    return results
