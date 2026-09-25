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

## PM2

Másold le a `.env.example` fájlt `.env` néven, majd állíts be egy hosszú, egyedi jelszót. A PM2 a Gitből kizárt `.env` fájlt automatikusan betölti:

```bash
pm2 start ecosystem.config.cjs
pm2 save
```

## Biztonság

Az alkalmazás csak belső vagy VPN-címre figyeljen. Nyilvános eléréshez HTTPS-re beállított Nginx szükséges. Az `APP_USER` és `APP_PASSWORD` környezeti változókat kötelező beállítani. Switch-jelszót az alkalmazásban ne tárolj.
