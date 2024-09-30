#pragma once

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "http_fs.h"

static esp_err_t http_server_get_handler(httpd_req_t *req)
{
 return file_get(req, req->uri);
  //size_t buf_len;
  //esp_err_t ret = ESP_OK;

  //ESP_LOGI("GET", "%s", req->uri);

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  /* char *host = nullptr;
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1)
  {
    host = (char *)malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Host", host, buf_len) != ESP_OK)
    {
      free(host);
      host = nullptr;
    }
  } */


  /* determine if Host is from the STA IP address */
  // wifi_manager_lock_sta_ip_string(portMAX_DELAY);
  // bool access_from_sta_ip = host != NULL ? strstr(host, wifi_manager_get_sta_ip_string()) : false;
  // wifi_manager_unlock_sta_ip_string();

  /* if (host != NULL && !strstr(host, DEFAULT_AP_IP) && !access_from_sta_ip)
  {

    // Captive Portal functionality
    // 302 Redirect to IP of the access point
    httpd_resp_set_status(req, http_302_hdr);
    httpd_resp_set_hdr(req, http_location_hdr, http_redirect_url);
    httpd_resp_send(req, NULL, 0);
  } */

  // memory clean up
  /* if (host != nullptr)
  {
    free(host);
  } */

  //return ret;
}

/// @brief Команди роботи з файловою системою
static esp_err_t post_fs_handler(httpd_req_t *req)
{
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  if (req->content_len > 1024)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content_len > 1024");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
  }

  char *body = (char *)malloc(sizeof(char) * req->content_len + 1);
  if (httpd_req_recv(req, body, req->content_len + 1) <= 0)
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive");
  else
  {
    cJSON *json = cJSON_Parse(body);
    if (json == NULL)
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed parse json");
    else
    {
      http_handle_command(req, json);
      cJSON_Delete(json);
    }
  }

  httpd_resp_sendstr_chunk(req, NULL);
  free(body);

  return ESP_OK;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static const httpd_uri_t http_server_post_fs_upload_request = {
    .uri = "/fs/upload",
    .method = HTTP_POST,
    .handler = post_upload_file};

static const httpd_uri_t http_server_post_fs_request = {
    .uri = "/fs",
    .method = HTTP_POST,
    .handler = post_fs_handler};

static const httpd_uri_t http_server_get_request = {
    .uri = "*",
    .method = HTTP_GET,
    .handler = http_server_get_handler};

#pragma GCC diagnostic pop

static esp_err_t register_fs_command_handler(httpd_handle_t handle)
{
  fs_mount();
  esp_err_t ret = httpd_register_uri_handler(handle, &http_server_post_fs_upload_request);
  if (ret != ESP_OK)
    return ret;
  ret = httpd_register_uri_handler(handle, &http_server_post_fs_request);
  return ret;
}

static esp_err_t register_fs_getfile_handler(httpd_handle_t handle)
{
  fs_mount();
  // fs_unmount();
  return httpd_register_uri_handler(handle, &http_server_get_request);
}