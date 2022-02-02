import vulners
from config import VULNERS_API_KEY

vulners_api = vulners.Vulners(api_key=VULNERS_API_KEY)