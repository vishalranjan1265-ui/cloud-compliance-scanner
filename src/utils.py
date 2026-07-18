import time
import logging
from typing import List, Dict, Any, Callable
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("CloudScanner.Utils")

def get_session(region: Optional[str] = None) -> boto3.Session:
    try:
        return boto3.Session(region_name=region)
    except Exception as e:
        logger.critical(f"Failed to initialize AWS baseline operational context: {str(e)}")
        raise

def get_operational_regions(session: boto3.Session) -> List[str]:
    try:
        ec2_client = session.client("ec2", region_name="us-east-1")
        response = ec2_client.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in response.get("Regions", [])]
    except ClientError as e:
        logger.error(f"Failed to query enabled regions. Falling back to primary sectors: {str(e)}")
        return ["us-east-1", "us-west-2", "eu-west-1"]

def rate_limiter_fallback(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        max_attempts = 4
        backoff = 2.0
        for attempt in range(max_attempts):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ["Throttling", "RequestLimitExceeded"] and attempt < max_attempts - 1:
                    sleep_duration = backoff ** (attempt + 1)
                    logger.warning(f"AWS API Throttling encountered. Invoking backoff handler for {sleep_duration}s...")
                    time.sleep(sleep_duration)
                else:
                    raise e
    return wrapper