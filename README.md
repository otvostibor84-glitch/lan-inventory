# LAN leltár

Egyszerű belső webalkalmazás switchek, portok, VLAN-ok és MAC-címek nyilvántartására.

## Követelmények

- Node.js 22.5 vagy újabb
- npm
- éles környezetben PM2 és Nginx

## Helyi indítás

```bash
npm install
set APP_USER=admin
set APP_PASSWORD=valassz-hosszu-jelszot
npm start
```

Az adatbázis első indításkor a `data/inventory.sqlite` fájlban jön létre. A `data` könyvtár nincs Gitbe mentve.

## Biztonság

Az alkalmazás a VPS-en csak a `127.0.0.1:3000` címen figyeljen, elé pedig HTTPS-re beállított Nginx kerüljön. Az `APP_USER` és `APP_PASSWORD` környezeti változókat kötelező beállítani. Switch-jelszót az alkalmazásban ne tárolj.
