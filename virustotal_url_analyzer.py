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
    home_view = WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'home-view')))
    shadow_root0 = driver.execute_script('return arguments[0].shadowRoot', home_view)
    url_search_in = shadow_root0.find_element(By.CSS_SELECTOR, 'input[id="urlSearchInput"]')
    url_search_in.send_keys(url_to_check)
    url_search_in.send_keys(Keys.ENTER)

    try:
        shadow_host0  = WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'url-view')))
        shadow_root0  = driver.execute_script('return arguments[0].shadowRoot', shadow_host0)
        shadow_host1  = shadow_root0.find_element(By.CSS_SELECTOR, 'vt-ui-detections-list[type="url"]')
        shadow_root1  = driver.execute_script('return arguments[0].shadowRoot', shadow_host1)
        shadow_host2  = shadow_root1.find_element(By.CSS_SELECTOR, 'div[id="detections"]')
        hstacks       = shadow_host2.find_elements(By.CSS_SELECTOR,'div[class="detection hstack"]')
        shadow_root10 = driver.execute_script('return arguments[0].shadowRoot', shadow_host0)
        shadow_host10 = shadow_root10.find_element(By.CSS_SELECTOR, 'vt-ui-main-generic-report[id="report"]')
        shadow_root11 = driver.execute_script('return arguments[0].shadowRoot', shadow_host10)
        shadow_host11 = shadow_root11.find_element(By.CSS_SELECTOR, "vt-ui-detections-widget")
        shadow_root12 = driver.execute_script('return arguments[0].shadowRoot', shadow_host11)
        positives     = shadow_root12.find_element(By.CSS_SELECTOR, 'div[class="positives"]').text
        total         = shadow_root12.find_element(By.CSS_SELECTOR, 'div[class="total"]').text
        
        for _, hstack in enumerate(hstacks):
            engine_name = hstack.find_element(By.CSS_SELECTOR, 'span[class="engine-name"]').text
            indiv_detect = hstack.find_element(By.CSS_SELECTOR, 'span[class="individual-detection"]').text
            if indiv_detect in rating_keys:
                for element in rating_list:
                    for a_key in element.keys():
                        if indiv_detect == a_key:
                            element[a_key].append(engine_name)
                            break
        results = {
            "url_to_check": url_to_check,
            "provider"    : "virustotal.com",
            "positives"   : positives,
            "total"       : total,
            "details"     : rating_list,
        }
    except Exception as error:
        print("VT rating cannot be performed.")
        print("Error:")
        print(error)

    return results

if __name__ == "__main__":
    print("Library for checking url reputation with vt.")
    ### To perform an example checkout,
    ### uncomment the lines below and fill in the value of "url_to_check"
    # url_to_check = "your_suspicious_url"
    # options = webdriver.ChromeOptions()
    # options.detach = True
    # driver = webdriver.Chrome(options=options)
    # results = vt_url_analyzer(driver=driver, url_to_check=url_to_check)
    # print(results)
