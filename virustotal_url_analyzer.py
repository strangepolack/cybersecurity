import sys
sys.dont_write_bytecode = 1

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

provider = "virustotal.com"
provider_url = "https://" + provider + "/gui/home/url/"

def vt_url_analyzer(driver, url_to_check):
    '''
    Requires installed selenium driver for your browser, as well as selenium python package.
    Example usage:
        vt_url_analyzer(driver=your_selenium_driver, url_to_check=your_suspicious_url)
    Returns:
        results - dictionary 
    '''
    def wait_for_elem(driver, time, elem):
        return WebDriverWait(driver, time).until(EC.visibility_of_element_located((By.CSS_SELECTOR, elem)))
    
    positives = "Unrated"
    total = "Unrated"
    results = {
            "url_to_check": url_to_check,
            "provider"    : "virustotal.com",
            "positives"   : "Unrated",
            "total"       : "Unrated",
            "details"     : [],
        }
    rating_list = [
        {"Malicious" : []},
        {"Phishing"  : []},
        {"Suspected" : []},
        {"Unrated"   : []},
        {"Clean"     : []},
    ]
    temp_rating_keys = [elem.keys() for elem in rating_list]
    rating_keys = []
    for elem in temp_rating_keys:
        for a_key in elem:
            rating_keys.append(a_key)

    driver.get(provider_url)
    home_view = wait_for_elem(driver=driver, time=10, elem='home-view')
    shadow_root0 = driver.execute_script('return arguments[0].shadowRoot', home_view)
    url_search_in = wait_for_elem(driver=shadow_root0, time=10, elem='input[id="urlSearchInput"]')
    url_search_in.send_keys(url_to_check)
    url_search_in.send_keys(Keys.ENTER)

    try:
        shadow_host12 = wait_for_elem(driver=driver, time=10, elem='url-view')
    except Exception as error:
        print("Main view unavaiable.")
        print("Error:")
        print(error)
    
    try:
        shadow_root11 = driver.execute_script('return arguments[0].shadowRoot', shadow_host12)
        shadow_host10 = wait_for_elem(driver=shadow_root11, time=10, elem='url-detection')
        shadow_root09 = driver.execute_script('return arguments[0].shadowRoot', shadow_host10)
        shadow_host08 = wait_for_elem(driver=shadow_root09, time=10, elem='vt-ui-detections-list[type="url"]')
        shadow_root07 = driver.execute_script('return arguments[0].shadowRoot', shadow_host08)
        shadow_host06 =  wait_for_elem(driver=shadow_root07, time=10, elem='div[id="detections"]')
        hstacks = shadow_host06.find_elements(By.CSS_SELECTOR,'div[class="detection hstack"]')
        
        for _, hstack in enumerate(hstacks):
            engine_name  = hstack.find_element(By.CSS_SELECTOR, 'span[class="engine-name"]').text
            indiv_detect = hstack.find_element(By.CSS_SELECTOR, 'span[class="individual-detection"]').text
            if indiv_detect in rating_keys:
                for element in rating_list:
                    for a_key in element.keys():
                        if indiv_detect == a_key:
                            element[a_key].append(engine_name)
                            break

    except Exception as error:
        print("VT detailed results unavaiable.")
        print("Error:")
        print(error)

    try:
        shadow_root03 = driver.execute_script('return arguments[0].shadowRoot', shadow_host12)
        shadow_host02 = wait_for_elem(driver=shadow_root03, time=10, elem="vt-ui-detections-widget")
        shadow_root01 = driver.execute_script('return arguments[0].shadowRoot', shadow_host02)
        positives = shadow_root01.find_element(By.CSS_SELECTOR, 'div[class="positives"]').text
        total = (wait_for_elem(driver=shadow_root01, time=10, elem='div[class="total"]')).text

        results = {
            "url_to_check": url_to_check,
            "provider"    : "virustotal.com",
            "positives"   : positives,
            "total"       : total,
            "details"     : rating_list,
        }
    except Exception as error:
        print("VT rating numbers cannot be performed.")
        print("Error:")
        print(error)
    return results


if __name__ == "__main__":
    print("Library for checking url reputation with vt.")
    ### To perform an example checkout,
    ### uncomment the lines below and fill in the value of "url_to_check".
    # url_to_check = "your_suspicious_url"
    # options = webdriver.ChromeOptions()
    # options.detach = True
    # driver = webdriver.Chrome(options=options)
    # results = vt_url_analyzer(driver=driver, url_to_check=url_to_check)
    # print(results)
