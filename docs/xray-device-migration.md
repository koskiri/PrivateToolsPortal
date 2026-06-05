# Миграция Xray на раздельные профили Android/Windows

Патч не переключает `xray.service` на чтение директории `conf.d` автоматически. Перед переключением нужно отдельно подготовить и проверить два файла конфигурации:

- Android: `/usr/local/etc/xray/conf.d/00-android.json`, inbound port `8443`.
- Windows: `/usr/local/etc/xray/conf.d/02-windows.json`, inbound port `8444`.

В `conf.d` не должно быть двух inbound с одинаковым `port`: при запуске `xray run -confdir /usr/local/etc/xray/conf.d` Xray загрузит все JSON-файлы из директории, и дубли портов не дадут сервису стартовать.

## Проверка конфигов на DE VPS до переключения systemd

```bash
sudo install -d -m 755 /usr/local/etc/xray/conf.d
sudo chmod 755 /usr/local/etc/xray /usr/local/etc/xray/conf.d
sudo chmod 644 /usr/local/etc/xray/conf.d/00-android.json /usr/local/etc/xray/conf.d/02-windows.json
sudo xray run -test -config /usr/local/etc/xray/conf.d/00-android.json
sudo xray run -test -config /usr/local/etc/xray/conf.d/02-windows.json
```

Если Xray пишет логи в `/var/log/xray`, проверьте права перед перезапуском сервиса:

```bash
sudo install -d -m 755 /var/log/xray
sudo chmod 755 /var/log/xray
sudo find /var/log/xray -maxdepth 1 -type f -name '*.log' -exec chmod 664 {} +
```

## Переключение systemd только после успешных тестов

После успешной проверки обоих файлов можно перевести сервис на загрузку директории:

```bash
sudo systemctl edit xray.service
```

В override-файл добавьте:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray/conf.d
```

Затем примените изменения:

```bash
sudo systemctl daemon-reload
sudo systemctl restart xray.service
sudo systemctl status xray.service --no-pager
```

## Проверки после деплоя

1. Создать Android-ключ через сайт и убедиться, что UUID добавился в `/usr/local/etc/xray/conf.d/00-android.json`.
2. Создать Windows-ключ через сайт и убедиться, что UUID добавился в `/usr/local/etc/xray/conf.d/02-windows.json`.
3. Проверить, что `xray.service` в состоянии `active (running)`.
4. Проверить, что Android payload содержит порт `8443`, а Windows payload содержит порт `8444`.
5. Проверить, что iPhone/macOS возвращают заглушку и не создают Xray-клиента.
