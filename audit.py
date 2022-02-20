import vulners
import json
from config import VULNERS_API_KEY


vulners_api = vulners.VulnersApi(api_key=VULNERS_API_KEY)


def read_astra_packages():
    with open("astra_packages_versions.txt", "r") as f:
        astra_packages = f.readlines()
    return astra_packages


def get_package_cvelist(package):
    package_cvelist = vulners_api.os_audit(os="debian",
                                       version="9",
                                       packages=[package]
                                       )
    return package_cvelist["cvelist"]


def astra_cve_full_mapping(save=False, out_to="astra_cve_list.json"):
    """You can get JSON object with all CVE in Astra Linux

    This is return JSON-object {package1:[CVE_list], package2:[CVE_list]....}
    If you want save results, set variable save=True (False by default).
    Default file to save - astra_cve_list.json
    You can define filename to save results - set variable out_to="file_to_save.json

    """

    result = {}
    astra_packages = read_astra_packages()
    for package in astra_packages:
        result.update({package:get_package_cvelist(package)})

    if save:
        with open(out_to, "w") as f:
            f.write(json.dumps(result, sort_keys=True, indent=5))

    return result


def confirm_cve_in_astra(cve_id):
    astra_cve_list = astra_cve_full_mapping()
    for i in astra_cve_list:
        if cve_id in astra_cve_list[i]:
            return True
    return False

'''
It is content some objects, such as are:
    packages
    vulnerabilities - list with DSA and DLA
    reasons - 
    cvss
    cvelist - list vith CVEs
    cumulativeFix
    id
'''
