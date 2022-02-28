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


def update_local_json():
    astra_cve_full_mapping(save=True)


def confirm_cve_in_astra(cve_id, local_db=False, local_json=False):
    """You can confirm single CVE in Astra Linux

    This is return True, if CVE is confirmed.
    Example: confirm_cve_in_astra("CVE-2021-4034")
    Set local_db=True (False by default), if you want search CVE in local database.

    """
    if local_json:
        if os.path.exists("astra_cve_list.json"):
            with open("astra_cve_list.json") as f:
                astra_cve_list = json.load(f)

            vulnerabilities = []
            for i in astra_cve_lists:
                if cve_id in astra_cve_list[i]:
                    vulnerabilities.append({i: cve_id})

        else:
            print("Need update local json")
            return False
    if local_db:
        pass

    else:
        vulnerabilities = []
        astra_cve_list = astra_cve_full_mapping()
        for i in astra_cve_list:
            if cve_id in astra_cve_list[i]:
                vulnerabilities.append({i:cve_id})

    if vulnerabilities:
        print(vulnerabilities)
        return True
    else:
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
