import vulners
from config import VULNERS_API_KEY

vulners_api = vulners.VulnersApi(api_key=VULNERS_API_KEY)

'''
Example audit packages vulns
package_vulns = vulners_api.os_audit(os="debian", version="9", packages=["libpolkit-agent-1-0 0.105-18astra.se1 amd64"]))

get CVE list
package_vulns["cvelist"]
['CVE-2019-6133', 'CVE-2018-19788', 'CVE-2021-4034']

'''
