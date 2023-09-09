#pragma once

#include "cJSON.h"
#include "esp_flash_partitions.h"
#include "esp_http_server.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "ff.h"
#include "Core.h"

#define MAX_FILE_SIZE (1024 * 1024) // 1 MB
#define MAX_FILE_SIZE_STR "1MB"

static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

const static char *base_path = "/fat";

static bool fsMounted = false;

static void normaliz_all();

static esp_err_t fs_mount()
{
  if (fsMounted)
    return ESP_OK;
  //ESP_LOGI("MOUNT", "Mounting FAT filesystem");
  // To mount device we need name of device partition, define base_path
  // and allow format partition in case if it is new one and was not formatted before
  const esp_vfs_fat_mount_config_t mount_config = {
      .format_if_mount_failed = true,
      .max_files = 4,
      .allocation_unit_size = CONFIG_WL_SECTOR_SIZE,
      .disk_status_check_enable = false};
  esp_err_t err;

  err = esp_vfs_fat_spiflash_mount_rw_wl(base_path, "storage", &mount_config, &s_wl_handle);

  if (err != ESP_OK)
  {
    ESP_LOGE("MOUNT", "Failed to mount FATFS (%s)", esp_err_to_name(err));
    return ESP_FAIL;
  }

  fsMounted = true;
  normaliz_all();
  return ESP_OK;
}

__attribute__((unused)) static esp_err_t fs_unmount()
{
  return esp_vfs_fat_unregister_path(base_path);
}

const static char *http_content_type[] = {
    "text/html",              // 0 html
    "image/jpeg",             // 1 jpeg
    "image/png",              // 2 png
    "image/x-icon",           // 3 ico
    "text/javascript",        // 4 js
    "text/css",               // 5 css
    "application/json",       // 6 json
    "application/font-woff2", // 7 woff2
    "text/plain"};            // 8 txt

const static char *http_content_type_ext[] = {
    ".html",  // 0 html
    ".jpeg",  // 1 jpeg
    ".png",   // 2 png
    ".ico",   // 3 ico
    ".js",    // 4 js
    ".css",   // 5 css
    ".json",  // 6 json
    ".woff2", // 7 woff2
    ""};      // 8 txt

const static uint8_t countTypes = 9;

// Set HTTP response content type according to file extension
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filename)
{
  for (uint8_t i = 0; i < countTypes - 1; i++)
    if (sizeof(http_content_type_ext[i]) == 1 ||
        cntstr(&filename[strlen(filename) - strlen(http_content_type_ext[i])], http_content_type_ext[i]))
      return httpd_resp_set_type(req, http_content_type[i]);

  return httpd_resp_set_type(req, "text/plain");
}

// Copies the full path into destination buffer and returns
// pointer to path (skipping the preceding base path)
static char *get_path_from_uri(const char *url, bool addBasePath = false)
{
  char *nurl = nullptr;

  if (cntstr(url, "/"))
    nurl = strdup("/index.html");
  else
  {
    nurl = strdup(url);

    int index = StringFindeCharIndex(nurl, '?', 0);
    if (index >= 0)
      nurl[index] = '\0';

    index = StringFindeCharIndex(nurl, '#', 0);
    if (index >= 0)
      nurl[index] = '\0';
  }

  if (!addBasePath)
    return nurl;

  int len = strlen(nurl) + strlen(base_path) + 2;
  char *path = (char *)malloc(sizeof(char) * len);
  snprintf(path, len, "%s/%s", base_path, nurl);
  free(nurl);

  return path;
}

static char *normalizeFileName(const char *dir, const char *filename)
{
  size_t len = strlen(filename);
  char *ret = strdup(filename);

  for (size_t i = 0; i < len; i++)
  {
    if (ret[i] < 32 || ret[i] > 126)
    {
      int len = (strlen(ret) + strlen(filename) + 2);
      char *fpath1 = (char *)malloc(sizeof(char) * len);
      snprintf(fpath1, len, "%s/%s", dir, ret);
      ret[i] = '\0';
      len = (strlen(ret) + strlen(filename) + 2);
      char *fpath2 = (char *)malloc(sizeof(char) * len);
      snprintf(fpath2, len, "%s/%s", dir, ret);
      //FRESULT res = 
      f_rename(fpath1, fpath2);
      //ESP_LOGI("RENAME", "FRESULT f_rename(\"%s\", \"%s\") == %i", fpath1, fpath2, res);
      free(fpath1);
      free(fpath2);
      break;
    }
  }
  return ret;
}

static FRESULT normaliz_path(char *path)
{
  FRESULT res;
  FF_DIR dir;
  uint8_t i;
  static FILINFO fno;

  res = f_opendir(&dir, path); // Open the directory
  if (res == FR_OK)
  {
    while (true)
    {
      res = f_readdir(&dir, &fno); // Read a directory item
      if (res != FR_OK || fno.fname[0] == 0)
        break; // Break on error or end of dir
      if (fno.fattrib & AM_DIR)
      { // It is a directory
        i = strlen(path);
        sprintf(&path[i], "%s", fno.fname);
        res = normaliz_path(path); // Enter the directory
        if (res != FR_OK)
          break;
        path[i] = 0;
      }
      else
      { // It is a file.
        normalizeFileName(path, fno.fname);
      }
    }
    f_closedir(&dir);
  }

  return res;
}

static void normaliz_all()
{
  char buff[256];

  strcpy(buff, "/\0");
  normaliz_path(buff);
}

const static char http_cache_control_hdr[] = "Cache-Control";
const static char http_cache_control_no_cache[] = "no-store, no-cache, must-revalidate, max-age=0";
const static char http_content_encoding_hdr[] = "Content-Encoding";
const static char http_content_encoding_gzip[] = "gzip";
// const static char http_cache_control_cache[] = "public, max-age=31536000";

static esp_err_t file_get(httpd_req_t *req, const char *url)
{
  FIL fdst; // File objects
  UINT br;  // File read count

  char *filename = get_path_from_uri(url);

  char *filename_gzip = (char *)malloc(sizeof(char) * (strlen(filename) + 4));
  sprintf(filename_gzip, "%s.gz", filename);
  FRESULT fr = f_open(&fdst, filename_gzip, FA_READ);

  if (fr == FR_OK)
  {
    httpd_resp_set_hdr(req, http_content_encoding_hdr, http_content_encoding_gzip);
  }
  else
  {
    fr = f_open(&fdst, filename, FA_READ);
  }

  if (fr == FR_NO_FILE)
  {
    free(filename);
    filename = strdup("/index.html");
    fr = f_open(&fdst, filename, FA_READ);
  }

  httpd_resp_set_hdr(req, http_cache_control_hdr, http_cache_control_no_cache);

  if (fr == FR_NO_FILE)
  {
    httpd_resp_send_404(req);
    free(filename);
    return ESP_FAIL;
  }
  if (fr != FR_OK)
  {
    httpd_resp_send_500(req);
    free(filename);
    return ESP_FAIL;
  }

  // Set conten type header
  set_content_type_from_file(req, filename);

  int buf_len = MIN(fdst.obj.objsize, 8192);
  char *buffer = (char *)malloc(buf_len); // File copy buffer

  // Copy source to destination
  do
  {
    fr = f_read(&fdst, buffer, buf_len, &br);
    if (httpd_resp_send_chunk(req, buffer, br) != ESP_OK)
    {
      // Respond with 500 Internal Server Error
      httpd_resp_send_500(req);
      break;
    }
  } while (br > 0);

  // Close open file
  fr = f_close(&fdst);

  free(filename);
  free(buffer);
  return ESP_OK;
}

static esp_err_t command_upload_file(httpd_req_t *req)
{
  if (req->content_len > MAX_FILE_SIZE)
  {
    //ESP_LOGE("UPLOAD", "File too large : %d bytes", req->content_len);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "File size must be less than " MAX_FILE_SIZE_STR "!");
    return ESP_FAIL;
  }

  FILE *fd = NULL;
  int buf_len = MIN(req->content_len, 8192);

  char *filename = (char *)malloc(256);
  httpd_req_get_hdr_value_str(req, "File-Name", filename, 256);

  char *path = get_path_from_uri(filename, true);
  free(filename);

  fd = fopen(path, "w");
  if (fd == NULL)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create file");
    free(path);
    return ESP_FAIL;
  }

  // Retrieve the pointer to scratch buffer for temporary storage
  char *buf = (char *)malloc(buf_len);
  int received;

  esp_err_t ret = ESP_OK;

  while (true)
  {
    received = httpd_req_recv(req, buf, buf_len);
    if (received == 0)
    {
      fclose(fd);
      break;
    }

    if (received <= 0)
    {
      if (received == HTTPD_SOCK_ERR_TIMEOUT)
        // Retry if timeout occurred
        continue;

      // In case of unrecoverable error,
      // close and delete the unfinished file
      fclose(fd);
      unlink(path);

      ESP_LOGI("DEBUG", "%i", received);

      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive file");
      ret = ESP_FAIL;
      break;
    }

    // Write buffer content to file on storage
    if (received != fwrite(buf, 1, received, fd))
    {
      // Couldn't write everything to file!
      // Storage may be full?
      fclose(fd);
      unlink(path);

      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to write file to storage. Storage may be full?");
      ret = ESP_FAIL;
      break;
    }
  }

  httpd_resp_send_chunk(req, NULL, 0);
  free(path);
  return ret;
}

static esp_err_t command_ls(httpd_req_t *req, const char *path)
{
  FF_DIR dir;
  FRESULT res = f_opendir(&dir, path); /* Open the directory */
  //ESP_LOGI("LS", "FRESULT f_opendir(\"%s\") == %i", path, res);
  if (res != FR_OK)
  {
    return ESP_FAIL;
  }

  httpd_resp_sendstr_chunk(req, "[");
  do
  {
    FILINFO fno;
    res = f_readdir(&dir, &fno); // Read a directory item
    if (res != FR_OK || fno.fname[0] == 0)
      break; // Break on error or end of dir
    if (fno.fattrib & AM_DIR)
    { // It is a directory
      const static char *mask = "{\"type\":\"directory\",\"name\":\"%s\"},";
      int len = snprintf(NULL, 0, mask, fno.fname) + 1;
      char *chunk = (char *)malloc(sizeof(char) * len);
      snprintf(chunk, len, mask, fno.fname);
      httpd_resp_sendstr_chunk(req, chunk);
      free(chunk);
    }
    else
    { // It is a file.
      const static char *mask = "{\"type\":\"file\",\"name\":\"%s\",\"size\":%lu,\"date\":%lu,\"time\":%lu,\"attrib\":%i},";
      int len = snprintf(NULL, 0, mask, fno.fname, fno.fsize, fno.fdate, fno.ftime, fno.fattrib) + 1;
      char *chunk = (char *)malloc(sizeof(char) * len);
      snprintf(chunk, len, mask, fno.fname, fno.fsize, fno.fdate, fno.ftime, fno.fattrib);
      httpd_resp_sendstr_chunk(req, chunk);
      //ESP_LOGI("LS", "%s", chunk);
      free(chunk);
    }
  } while (res == FR_OK);

  f_closedir(&dir);
  httpd_resp_sendstr_chunk(req, "]");

  return ESP_OK;
}

static esp_err_t command_mkdir(httpd_req_t *req, const char *path)
{
  FRESULT res = f_mkdir(path);
  if (res > 0)
    return ESP_OK;

  return ESP_FAIL;
}

static esp_err_t command_rm(httpd_req_t *req, const char *path, bool recursive)
{
  FRESULT res = f_unlink(path);
  if (res > 0)
    return ESP_OK;

  return ESP_FAIL;
}

static esp_err_t command_mv(httpd_req_t *req, const char *old, const char *newc)
{
  FRESULT res = f_rename(old, newc);
  if (res > 0)
    return ESP_OK;

  return ESP_FAIL;
}

// Список команд файлової системи

/*
ls - список файлів і папок в папці
{"path":"/js"}

mkdir - створити папку
{"path":"/"}

rm
{"path":"/js", "recursive":true}

mv
{"old":"/oldname", "new":"/newname"}
*/
static esp_err_t handle_command(httpd_req_t *req, const char *command, cJSON *data)
{
  if (cntstr(command, "ls"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;
    return command_ls(req, path->valuestring);
  }

  if (cntstr(command, "mkdir"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;
    return command_mkdir(req, path->valuestring);
  }

  if (cntstr(command, "rm"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;

    bool rec = false;
    cJSON *recursive = cJSON_GetObjectItem(data, "name");
    if (recursive != NULL)
      rec = cJSON_IsTrue(recursive) == 0;
    return command_rm(req, path->valuestring, rec);
  }

  if (cntstr(command, "mv"))
  {
    cJSON *old = cJSON_GetObjectItem(data, "old");
    if (!cJSON_IsString(old) || (old->valuestring == NULL))
      return ESP_FAIL;
    cJSON *newn = cJSON_GetObjectItem(data, "new");
    if (!cJSON_IsString(newn) || (newn->valuestring == NULL))
      return ESP_FAIL;
    return command_mv(req, old->valuestring, newn->valuestring);
  }

  return ESP_FAIL;
}

static esp_err_t http_handle_command(httpd_req_t *req, cJSON *json)
{
  cJSON *command = cJSON_GetObjectItem(json, "command");
  if (!cJSON_IsString(command) || (command->valuestring == NULL))
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed parse json command");
    return ESP_FAIL;
  }

  cJSON *data = cJSON_GetObjectItem(json, "data");
  if (!cJSON_IsObject(data))
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed parse json data");
    return ESP_FAIL;
  }

  return handle_command(req, command->valuestring, data);
}