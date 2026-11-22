"""Yönetim komutları.

  python manage.py yonetici-olustur <kullanıcı>      yeni yönetici (şifre sorulur)
  python manage.py sifre-sifirla <kullanıcı>         şifre sıfırla (ilk girişte değiştirilecek)
  python manage.py baglanti-test                      Cloudflare ve Picus bağlantı testi
"""
import getpass
import sys

from werkzeug.security import generate_password_hash

import cfapi
import config
import db
import picusapi


def _pw():
    p = getpass.getpass("Şifre (en az 10 karakter): ")
    if len(p) < 10 or p != getpass.getpass("Tekrar: "):
        sys.exit("Şifre en az 10 karakter olmalı ve iki giriş aynı olmalı.")
    return generate_password_hash(p)


def main():
    db.init_db()
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, con = sys.argv[1], db.connect()
    if cmd == "yonetici-olustur" and len(sys.argv) == 3:
        con.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES(?, ?, 'admin', ?)", (sys.argv[2], _pw(), db.now_utc()))
        con.commit()
        print("Yönetici oluşturuldu.")
    elif cmd == "sifre-sifirla" and len(sys.argv) == 3:
        n = con.execute("UPDATE users SET pw_hash=?, must_change=1, active=1 WHERE username=?", (_pw(), sys.argv[2])).rowcount
        con.commit()
        print("Şifre sıfırlandı." if n else "Kullanıcı bulunamadı.")
    elif cmd == "baglanti-test":
        try:
            ok, msg = cfapi.CFClient(config.cf_token(), db.setting(con, "zone_id")).test()
            print(("[OK] " if ok else "[HATA] ") + "Cloudflare: " + msg)
        except cfapi.CFError as e:
            print("[HATA] Cloudflare:", e)
        if config.picus_token():
            try:
                print("[OK] Picus:", picusapi.PicusClient(config.picus_token(), config.PICUS_URL).test())
            except picusapi.PicusError as e:
                print("[HATA] Picus:", e)
        else:
            print("[-] Picus: PICUS_API_TOKEN tanımlı değil (isteğe bağlı).")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
