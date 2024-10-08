#pragma once

#include "Core.h"
#include "cJSON.h"
#include "esp_flash_partitions.h"
#include "esp_http_server.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "ff.h"

#define MAX_FILE_SIZE (1024 * 1024) // 1 MB
#define MAX_FILE_SIZE_STR "1MB"

static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

const static char *base_path = "/fat";

const static char *partitionName = "storage";

static bool fsMounted = false;

static void fixAllFileNames();

static esp_err_t fs_mount()
{
  if (fsMounted)
    return ESP_OK;
  // To mount device we need name of device partition, define base_path
  // and allow format partition in case if it is new one and was not formatted before
  esp_vfs_fat_mount_config_t mount_config = VFS_FAT_MOUNT_DEFAULT_CONFIG();
  mount_config.format_if_mount_failed = true;

  // esp_vfs_fat_spiflash_format_cfg_rw_wl
  esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(base_path, partitionName, &mount_config, &s_wl_handle);

  if (err != ESP_OK)
  {
    ESP_LOGE("FatFS", "Failed to mount FATFS (%s)", esp_err_to_name(err));
    return ESP_FAIL;
  }

  fsMounted = true;
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
    "image/svg+xml",          // 8 svg
    "text/plain"};            // 9 txt

const static char *http_content_type_ext[] = {
    ".html",  // 0 html
    ".jpeg",  // 1 jpeg
    ".png",   // 2 png
    ".ico",   // 3 ico
    ".js",    // 4 js
    ".css",   // 5 css
    ".json",  // 6 json
    ".woff2", // 7 woff2
    ".svg",   // 8 svg
    ""};      // 9 txt

const static uint8_t countTypes = 10;

/**
 * @brief Set HTTP response content type according to file extension.
 * @param req request context.
 * @param filename supported name.html .jpeg .png .ico .js .css .json .woff2 (others text/plain)
 * @return esp_err_t
 */
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filename)
{
  for (uint8_t i = 0; i < countTypes - 1; i++)
    if (sizeof(http_content_type_ext[i]) == 1 ||
        cmpstr(&filename[strlen(filename) - strlen(http_content_type_ext[i])], http_content_type_ext[i]))
      return httpd_resp_set_type(req, http_content_type[i]);

  return httpd_resp_set_type(req, http_content_type[countTypes - 1]);
}

/**
 * @brief converts a url to a path to a file in the FATFS.
 * @param url
 * @param addBasePath true if you want to add base_path to the file path.
 * @return char* the full path to the file in the FATFS.
 */
static char *get_path_from_uri(const char *url, bool addBasePath = false)
{
  char *nurl = nullptr;

  if (cmpstr(url, "/"))
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
      f_rename(fpath1, fpath2);
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

/**
 * @brief if using the FatFs generator directly from the CMake build system by calling.
 * maybe a mistake? if the file name is 18 characters, the file is written with an incorrect name,
 * this function is intended to fix this error.
 * Example file name:
 * 351.baa8b638.js.gz recorded as 351.baa8b638.js.gz￿￿￿￿￿￿￿￿
 * vendor.4b625066.js recorded as vendor.4b625066.js￿￿￿￿￿￿￿￿
 */
static void fixAllFileNames()
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

  char *filePath = get_path_from_uri(url);
  char *openFilePath = nullptr;
  FRESULT fr;

  // try opening the gzip file if it exists
  const static char *patterm = "%s.gz";
  int length = snprintf(nullptr, 0, patterm, filePath) + 1;
  openFilePath = (char *)malloc(sizeof(char) * length);
  snprintf(openFilePath, length, patterm, filePath);
  fr = f_open(&fdst, openFilePath, FA_READ);

  if (fr != FR_OK)
  {
    // gziped file does not exist, try to open a regular file
    free(openFilePath);
    openFilePath = strdup(filePath);
    fr = f_open(&fdst, openFilePath, FA_READ);
  }
  else
    httpd_resp_set_hdr(req, http_content_encoding_hdr, http_content_encoding_gzip);

  if (fr == FR_NO_FILE)
  {
    free(openFilePath);
    openFilePath = strdup("/index.html");
    fr = f_open(&fdst, openFilePath, FA_READ);
  }

  httpd_resp_set_hdr(req, http_cache_control_hdr, http_cache_control_no_cache);

  if (fr != FR_OK)
  {
    if (fr == FR_NO_FILE)
      httpd_resp_send_404(req);
    else
      httpd_resp_send_500(req);
    free(filePath);
    free(openFilePath);
    return ESP_FAIL;
  }

  // Set header content type. filePath instead of openFilePath because openFilePath can have a .gz extension
  set_content_type_from_file(req, filePath);
  free(filePath);

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

  free(openFilePath);
  free(buffer);
  return ESP_OK;
}

static esp_err_t post_upload_file(httpd_req_t *req)
{
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  if (req->content_len > MAX_FILE_SIZE)
  {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "File size must be less than " MAX_FILE_SIZE_STR "!");
    return ESP_FAIL;
  }

  size_t filename_len = httpd_req_get_hdr_value_len(req, "X-File-Name");
  if (filename_len <= 0)
  {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "need X-File-Name header");
    return ESP_FAIL;
  }

  char *filename = (char *)malloc(filename_len + 1);
  httpd_req_get_hdr_value_str(req, "X-File-Name", filename, filename_len + 1);

  char *path = get_path_from_uri(filename, true);
  free(filename);

  FILE *fd = NULL;
  fd = fopen(path, "w");
  if (fd == NULL)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create file");
    free(path);
    return ESP_FAIL;
  }

  // Retrieve the pointer to scratch buffer for temporary storage
  int buf_len = MIN(req->content_len, 8192);
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
  if (res != FR_OK)
  {
    return ESP_FAIL;
  }

  httpd_resp_sendstr_chunk(req, "[");
  uint16_t indexer = 0;
  do
  {
    FILINFO fno;
    res = f_readdir(&dir, &fno); // Read a directory item
    if (res != FR_OK || fno.fname[0] == 0)
      break; // Break on error or end of dir

    if (indexer > 0)
    {
      httpd_resp_sendstr_chunk(req, ",");
    }
    indexer++;

    if (fno.fattrib & AM_DIR)
    { // It is a directory
      const static char *mask = "{\"type\":\"directory\",\"name\":\"%s\"}";
      int len = snprintf(NULL, 0, mask, fno.fname) + 1;
      char *chunk = (char *)malloc(sizeof(char) * len);
      snprintf(chunk, len, mask, fno.fname);
      httpd_resp_sendstr_chunk(req, chunk);
      free(chunk);
    }
    else
    { // It is a file.
      const static char *mask = "{\"type\":\"file\",\"name\":\"%s\",\"size\":%lu}";
      int len = snprintf(NULL, 0, mask, fno.fname, fno.fsize) + 1;
      char *chunk = (char *)malloc(sizeof(char) * len);
      snprintf(chunk, len, mask, fno.fname, fno.fsize);
      httpd_resp_sendstr_chunk(req, chunk);
      free(chunk);
    }
  } while (res == FR_OK);

  f_closedir(&dir);
  httpd_resp_sendstr_chunk(req, "]");

  return ESP_OK;
}

static esp_err_t command_mkdir(httpd_req_t *req, const char *path)
{
  return f_mkdir(path);
}

static esp_err_t command_rm(httpd_req_t *req, const char *path, bool recursive)
{
  return f_unlink(path);
}

static esp_err_t command_mv(httpd_req_t *req, const char *old, const char *newc)
{
  return f_rename(old, newc);
}

static esp_err_t command_info(httpd_req_t *req)
{
  uint64_t total_bytes = 0, free_bytes = 0;

  // Перевірка чи файлову систему змонтовано
  if (s_wl_handle == WL_INVALID_HANDLE)
  {
    // Відправляємо статус помилки
    httpd_resp_sendstr_chunk(req, "{\"status\":\"error\",\"message\":\"Файлова система не змонтована\"}");
    return ESP_OK;
  }

  const static char *mask = "%" PRIu64;

  // Отримання інформації про файлову систему
  esp_vfs_fat_info(base_path, &total_bytes, &free_bytes);

  // Відправляємо статус "ok"
  httpd_resp_sendstr_chunk(req, "{\"status\":\"ok\",");

  // Динамічно генеруємо та відправляємо поле "total_bytes"
  httpd_resp_sendstr_chunk(req, "\"total_bytes\":");
  int len = snprintf(NULL, 0, mask, total_bytes) + 1;
  char *total_bytes_buffer = (char *)malloc(len);
  snprintf(total_bytes_buffer, len, mask, total_bytes);
  httpd_resp_sendstr_chunk(req, total_bytes_buffer);
  free(total_bytes_buffer);

  // Відправляємо роздільник та поле "free_bytes"
  httpd_resp_sendstr_chunk(req, ",\"free_bytes\":");
  len = snprintf(NULL, 0, mask, free_bytes) + 1;
  char *free_bytes_buffer = (char *)malloc(len);
  snprintf(free_bytes_buffer, len, mask, free_bytes);
  httpd_resp_sendstr_chunk(req, free_bytes_buffer);
  free(free_bytes_buffer);

  // Закриваємо JSON-об'єкт
  httpd_resp_sendstr_chunk(req, "}");

  // Вказуємо завершення відправки
  httpd_resp_sendstr_chunk(req, NULL);

  return ESP_OK;
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

static esp_err_t handle_codereturn_command(httpd_req_t *req, const char *command, cJSON *data)
{
  if (cmpstr(command, "mkdir"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;
    return command_mkdir(req, path->valuestring);
  }

  if (cmpstr(command, "rm"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;

    bool rec = false;
    cJSON *recursive = cJSON_GetObjectItem(data, "recursive");
    if (recursive != NULL)
      rec = cJSON_IsTrue(recursive) == 0;
    return command_rm(req, path->valuestring, rec);
  }

  if (cmpstr(command, "mv"))
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

static esp_err_t handle_command(httpd_req_t *req, const char *command, cJSON *data)
{
  if (cmpstr(command, "ls"))
  {
    cJSON *path = cJSON_GetObjectItem(data, "path");
    if (!cJSON_IsString(path) || (path->valuestring == NULL))
      return ESP_FAIL;
    return command_ls(req, path->valuestring);
  }
  if (cmpstr(command, "info"))
  {
    return command_info(req);
  }

  esp_err_t err = handle_codereturn_command(req, command, data);
  if (err == ESP_OK)
  {
    httpd_resp_sendstr(req, "OK");
    return err;
  }

  int len = snprintf(NULL, 0, "%d", err) + 1;
  char *chunk = (char *)malloc(sizeof(char) * len);
  snprintf(chunk, len, "%d", err);
  httpd_resp_sendstr(req, chunk);
  free(chunk);

  return err;
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