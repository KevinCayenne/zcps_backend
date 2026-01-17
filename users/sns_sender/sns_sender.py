from abc import ABC, abstractmethod
import json
import logging
from users.sns_sender.utils import send_sms_bulk_by_mitake


class BaseSnsSender(ABC):
    def __init__(self, request: dict):
        self.request = request
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def build_sms_data(self) -> list:
        """
        Build the SMS data to be sent.
        This method should be implemented by subclasses.
        """

    def send(self) -> dict:
        sms_data_list = self.build_sms_data()
        self.logger.info(f"Send SMS to {len(sms_data_list)} users")

        if not sms_data_list:
            return {"success": True, "message": "No any users to send SMS."}

        results = send_sms_bulk_by_mitake(sms_data_list)
        fails = [result for result in results if not result[0]]
        if fails:
            self.logger.error(
                f"Failed to send SMS: {json.dumps(fails, ensure_ascii=False, indent=4)}"
            )
            return {"success": False, "message": fails}

        return {"success": True, "message": results, "total_users": len(sms_data_list)}
