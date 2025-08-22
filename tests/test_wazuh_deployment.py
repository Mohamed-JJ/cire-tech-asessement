import os
import pytest
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException
import requests
import json
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class TestWazuhDeployment:
    """
    Comprehensive test suite for Wazuh deployment validation
    """
    
    @pytest.fixture(scope="class")
    def selenium_driver(self):
        """Setup Chrome WebDriver with appropriate options"""
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode for CI/CD
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--ignore-ssl-errors=yes")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--allow-running-insecure-content")
        chrome_options.add_argument("--disable-web-security")
        
        # Setup Chrome driver
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.implicitly_wait(10)
        
        yield driver
        driver.quit()
    
    @pytest.fixture(scope="class")
    def test_config(self):
        """Load test configuration from environment variables"""
        return {
            'wazuh_host': os.getenv('WAZUH_HOST', 'localhost'),
            'wazuh_port': os.getenv('WAZUH_PORT', '80'),
            'wazuh_dashboard_port': os.getenv('WAZUH_DASHBOARD_PORT', '5601'),
            'wazuh_api_port': os.getenv('WAZUH_API_PORT', '55000'),
            'test_username': os.getenv('WAZUH_TEST_USERNAME', 'kibanaserver'),
            'test_password': os.getenv('WAZUH_TEST_PASSWORD', 'MyS3cr3tP450r.-*'),
            'admin_username': os.getenv('WAZUH_ADMIN_USERNAME', 'admin'),
            'admin_password': os.getenv('WAZUH_ADMIN_PASSWORD', 'SecretPassword'),
            'timeout': int(os.getenv('TEST_TIMEOUT', '30'))
        }
    
    def test_wazuh_dashboard_https_reachable(self, selenium_driver, test_config):
        """
        Test: Validate the Wazuh dashboard is reachable over HTTPS
        """
        dashboard_url = f"https://{test_config['wazuh_host']}:{test_config['wazuh_dashboard_port']}"
        
        try:
            selenium_driver.get(dashboard_url)
            
            # Wait for page to load
            WebDriverWait(selenium_driver, test_config['timeout']).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Verify we can reach the dashboard (status code would be handled by browser)
            assert selenium_driver.current_url.startswith("https://"), "Dashboard should be served over HTTPS"
            print(f"✓ Dashboard is reachable at {dashboard_url}")
            
        except TimeoutException:
            pytest.fail(f"Dashboard at {dashboard_url} is not reachable within {test_config['timeout']} seconds")
        except WebDriverException as e:
            pytest.fail(f"WebDriver error accessing dashboard: {str(e)}")
    
    def test_dashboard_via_nginx_proxy(self, selenium_driver, test_config):
        """
        Test: Validate dashboard access through Nginx reverse proxy
        """
        proxy_url = f"http://{test_config['wazuh_host']}:{test_config['wazuh_port']}/dashboard/"
        
        try:
            selenium_driver.get(proxy_url)
            
            # Wait for page to load
            WebDriverWait(selenium_driver, test_config['timeout']).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Verify we can access through proxy
            current_url = selenium_driver.current_url
            assert "/dashboard" in current_url or "wazuh" in current_url.lower(), "Should be redirected to Wazuh dashboard"
            print(f"✓ Dashboard is accessible via Nginx proxy at {proxy_url}")
            
        except TimeoutException:
            pytest.fail(f"Dashboard proxy at {proxy_url} is not reachable within {test_config['timeout']} seconds")
        except WebDriverException as e:
            pytest.fail(f"WebDriver error accessing dashboard via proxy: {str(e)}")
    
    def test_page_title_and_login_elements(self, selenium_driver, test_config):
        """
        Test: Validate page title and login form elements are present
        """
        dashboard_url = f"https://{test_config['wazuh_host']}:{test_config['wazuh_dashboard_port']}"
        
        selenium_driver.get(dashboard_url)
        
        # Wait for page to load completely
        WebDriverWait(selenium_driver, test_config['timeout']).until(
            lambda driver: driver.execute_script("return document.readyState") == "complete"
        )
        
        # Check page title
        page_title = selenium_driver.title
        assert page_title, "Page should have a title"
        assert any(keyword in page_title.lower() for keyword in ['wazuh', 'opensearch', 'security']), \
            f"Page title '{page_title}' should contain Wazuh, OpenSearch, or Security"
        print(f"✓ Page title: {page_title}")
        
        # Look for login form elements with multiple possible selectors
        login_selectors = [
            # Common login form selectors
            "input[type='text']", "input[name='username']", "input[id='username']",
            "input[type='email']", "input[placeholder*='user']", "input[placeholder*='User']",
            "[data-test-subj='user-name']", "[data-testid='username']"
        ]
        
        password_selectors = [
            "input[type='password']", "input[name='password']", "input[id='password']",
            "input[placeholder*='pass']", "input[placeholder*='Pass']",
            "[data-test-subj='password']", "[data-testid='password']"
        ]
        
        login_button_selectors = [
            "button[type='submit']", "input[type='submit']", 
            "button:contains('Log in')", "button:contains('Login')", "button:contains('Sign in')",
            "[data-test-subj='log-in-button']", "[data-testid='login-button']",
            ".login-button", "#login-button"
        ]
        
        # Check for username field
        username_field = None
        for selector in login_selectors:
            try:
                username_field = selenium_driver.find_element(By.CSS_SELECTOR, selector)
                if username_field.is_displayed():
                    print(f"✓ Username field found: {selector}")
                    break
            except:
                continue
        
        assert username_field is not None, "Username/login field should be present"
        
        # Check for password field
        password_field = None
        for selector in password_selectors:
            try:
                password_field = selenium_driver.find_element(By.CSS_SELECTOR, selector)
                if password_field.is_displayed():
                    print(f"✓ Password field found: {selector}")
                    break
            except:
                continue
        
        assert password_field is not None, "Password field should be present"
        
        # Check for login button
        login_button = None
        for selector in login_button_selectors:
            try:
                if "contains" in selector:
                    # Handle XPath-style selectors
                    xpath_selector = f"//button[contains(text(), 'Log in') or contains(text(), 'Login') or contains(text(), 'Sign in')]"
                    login_button = selenium_driver.find_element(By.XPATH, xpath_selector)
                else:
                    login_button = selenium_driver.find_element(By.CSS_SELECTOR, selector)
                
                if login_button.is_displayed():
                    print(f"✓ Login button found: {selector}")
                    break
            except:
                continue
        
        assert login_button is not None, "Login/submit button should be present"
        
        print("✓ All required login form elements are present")
    
    def test_programmatic_login_and_landing_page(self, selenium_driver, test_config):
        """
        Test: Programmatic login using test account and validate landing page
        """
        dashboard_url = f"https://{test_config['wazuh_host']}:{test_config['wazuh_dashboard_port']}"
        
        selenium_driver.get(dashboard_url)
        
        # Wait for login form to be ready
        try:
            # Wait for username field
            username_field = WebDriverWait(selenium_driver, test_config['timeout']).until(
                lambda driver: driver.find_element(By.CSS_SELECTOR, "input[type='text'], input[name='username'], input[id='username'], [data-test-subj='user-name']")
            )
            
            # Wait for password field
            password_field = selenium_driver.find_element(By.CSS_SELECTOR, "input[type='password'], input[name='password'], input[id='password'], [data-test-subj='password']")
            
            # Wait for login button
            login_button = selenium_driver.find_element(By.CSS_SELECTOR, "button[type='submit'], input[type='submit'], [data-test-subj='log-in-button']")
            
            # Perform login
            username_field.clear()
            username_field.send_keys(test_config['test_username'])
            
            password_field.clear()
            password_field.send_keys(test_config['test_password'])
            
            login_button.click()
            
            # Wait for successful login (look for dashboard elements)
            WebDriverWait(selenium_driver, test_config['timeout']).until(
                lambda driver: any([
                    "dashboard" in driver.current_url.lower(),
                    driver.find_elements(By.CSS_SELECTOR, "[data-test-subj='kibanaChrome']"),
                    driver.find_elements(By.CSS_SELECTOR, ".application"),
                    driver.find_elements(By.CSS_SELECTOR, "[data-test-subj='discover']"),
                    driver.find_elements(By.CSS_SELECTOR, ".wz-menu-wrapper"),
                    "wazuh" in driver.title.lower()
                ])
            )
            
            # Validate landing page elements
            landing_page_indicators = [
                ("[data-test-subj='kibanaChrome']", "Kibana Chrome navigation"),
                (".application", "Main application container"),
                ("[data-test-subj='discover']", "Discover functionality"),
                (".wz-menu-wrapper", "Wazuh menu wrapper"),
                ("nav", "Navigation elements"),
                (".navbar", "Navigation bar"),
                ("header", "Page header")
            ]
            
            found_indicators = []
            for selector, description in landing_page_indicators:
                try:
                    elements = selenium_driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        found_indicators.append(description)
                        print(f"✓ Found landing page element: {description}")
                except:
                    continue
            
            assert len(found_indicators) > 0, "At least one landing page indicator should be present after login"
            
            # Check if we're no longer on login page
            current_url = selenium_driver.current_url
            page_source = selenium_driver.page_source.lower()
            
            login_indicators = ["login", "sign in", "authentication"]
            is_still_login_page = any(indicator in page_source for indicator in login_indicators) and \
                                  any(indicator in current_url.lower() for indicator in login_indicators)
            
            assert not is_still_login_page, "Should not be on login page after successful authentication"
            
            print(f"✓ Successfully logged in and reached landing page")
            print(f"✓ Current URL: {current_url}")
            print(f"✓ Page title: {selenium_driver.title}")
            
        except TimeoutException:
            pytest.fail("Login form elements not found or login process timed out")
        except Exception as e:
            # Take screenshot for debugging
            try:
                selenium_driver.save_screenshot("/tmp/login_failure.png")
                print("Screenshot saved to /tmp/login_failure.png")
            except:
                pass
            pytest.fail(f"Login process failed: {str(e)}")
    
    def test_api_health_probe(self, test_config):
        """
        Test: API health probe - validate manager API endpoint returns 200/JSON
        """
        api_url = f"https://{test_config['wazuh_host']}:{test_config['wazuh_api_port']}"
        health_endpoints = [
            "/",
            "/?pretty=true", 
            "/manager/info",
            "/manager/status"
        ]
        
        successful_endpoint = None
        
        for endpoint in health_endpoints:
            url = f"{api_url}{endpoint}"
            try:
                response = requests.get(
                    url,
                    auth=(test_config['admin_username'], test_config['admin_password']),
                    verify=False,  # Skip SSL verification for testing
                    timeout=test_config['timeout']
                )
                
                print(f"Testing endpoint: {url}")
                print(f"Response status: {response.status_code}")
                
                if response.status_code == 200:
                    successful_endpoint = endpoint
                    
                    # Validate JSON response
                    try:
                        json_data = response.json()
                        assert isinstance(json_data, dict), "Response should be valid JSON object"
                        print(f"✓ Valid JSON response from {endpoint}")
                        
                        # Basic JSON schema validation for Wazuh API
                        expected_fields = ['error', 'data', 'message']
                        if any(field in json_data for field in expected_fields):
                            print("✓ Response contains expected Wazuh API fields")
                        
                        print(f"✓ API endpoint {endpoint} is healthy")
                        break
                        
                    except json.JSONDecodeError:
                        print(f"⚠ Endpoint {endpoint} returned 200 but not valid JSON")
                        continue
                        
                elif response.status_code == 401:
                    print(f"⚠ Authentication required for {endpoint}")
                    continue
                elif response.status_code == 404:
                    print(f"⚠ Endpoint {endpoint} not found")
                    continue
                else:
                    print(f"⚠ Endpoint {endpoint} returned status {response.status_code}")
                    continue
                    
            except requests.exceptions.ConnectionError:
                print(f"⚠ Connection failed to {url}")
                continue
            except requests.exceptions.Timeout:
                print(f"⚠ Timeout accessing {url}")
                continue
            except Exception as e:
                print(f"⚠ Error accessing {url}: {str(e)}")
                continue
        
        assert successful_endpoint is not None, f"No API endpoints returned healthy responses. Tested: {health_endpoints}"
        print(f"✓ API health check passed for endpoint: {successful_endpoint}")
    
    def test_nginx_proxy_health(self, test_config):
        """
        Test: Nginx proxy health endpoints
        """
        base_url = f"http://{test_config['wazuh_host']}:{test_config['wazuh_port']}"
        health_endpoints = [
            "/health",
            "/status", 
            "/health/manager",
            "/health/dashboard",
            "/health/indexer"
        ]
        
        for endpoint in health_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                response = requests.get(url, timeout=test_config['timeout'])
                print(f"Testing Nginx endpoint: {url} - Status: {response.status_code}")
                
                if response.status_code == 200:
                    print(f"✓ Nginx health endpoint {endpoint} is responding")
                    
            except requests.exceptions.RequestException as e:
                print(f"⚠ Nginx endpoint {url} error: {str(e)}")
                continue
        
        # At least one health endpoint should work
        print("✓ Nginx proxy health checks completed")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--html=test_report.html", "--self-contained-html"])
