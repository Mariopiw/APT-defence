# Projekt 5 — Secure Remote Logging & APT Evidence Vault

**Pełny, uruchamialny przewodnik PL — Linux Mint + oddzielny Ubuntu/Linux Collector**

Architektura: ThinkPad T460 (nadawca) → TCP 6514 z wzajemnym TLS (mTLS, x509/name) → oddzielny kolektor rsyslog → kopia logu → ledger SHA-256/HMAC → kotwica na niezależnym nośniku → skaner zagrożeń → raport i ręczna decyzja analityka.

> Uwaga: projekt jest LABORATORIUM defensywnym, nie certyfikowanym repozytorium WORM ani pełnym narzędziem forensic. Atakujący kontrolujący źródłowy system może przestać generować lub wysyłać prawdziwe logi. Klucz prywatny CA musi być przechowywany poza nadawcą i kolektorem. Oba systemy należy administrować niezależnie. Nie używaj prawdziwych adresów IP, nazw użytkowników ani kluczy w publicznym repozytorium.

## Etap 0 — Zasady bezpieczeństwa i sprzęt

- Host A: laptop Linux Mint XFCE, nadawca rsyslog. Działa lokalnie.
- Host B: odrębny komputer z Linuxem (np. Ubuntu Server), kolektor. Nie używaj tego samego konta administracyjnego ani tych samych haseł co na nadawcy.
- Host C: zaufany komputer administracyjny albo środowisko offline, generujące CA i certyfikaty.
- Ruch sieciowy: TYLKO sieć prywatna lub VPN. TCP 6514 dostępny tylko z rzeczywistego adresu IP nadawcy.
- Adresy i nazwy w ćwiczeniu: `logs.lab` (kolektor), `mint-sender.lab` (certyfikat nadawcy) — nazwy przykładowe, użyj lokalnego DNS/`/etc/hosts` i prywatnego adresu IP.
- Przed zmianami: kopie zapasowe, plan odzyskiwania SSH, weryfikacja czasu `timedatectl` na obu urządzeniach.
- W żadnym momencie nie kopiuj `ca.key` na host A albo B. Nigdy nie wysyłaj prywatnych kluczy do GitHuba.

## Etap 1 — Pobierz ZIP i sprawdź zawartość (NA KAŻDYM HOSTCIE)

```bash
sudo apt update
sudo apt install -y python3 rsyslog rsyslog-gnutls openssl ufw unzip
cd "$(xdg-user-dir DOWNLOAD)"  # Linux Mint; na Ubuntu Server użyj ~/Downloads lub właściwej ścieżki
unzip linux-apt-evidence-vault-kompletny-PL.zip
cd linux-apt-evidence-vault
find . -maxdepth 3 -type f | sort
python3 -m unittest discover -s tests -v
```

Archiwum przygotowano z katalogiem głównym `linux-apt-evidence-vault`. Jeżeli uruchamiasz Ubuntu Server bez katalogu Pobrane, przenieś ZIP np. do `~/` i wykonaj `cd ~` przed `unzip`.

Przed uruchomieniem skryptów instalacyjnych zapoznaj się z `scripts/install_sender.sh`, `scripts/install_collector.sh` i `scripts/remove_vault.sh`.

## Etap 2 — Demonstracja bez uprawnień root (DOWOLNY HOST)

```bash
cd linux-apt-evidence-vault
mkdir -p output
python3 -m vault hunt \
  --log samples/remote.log \
  --json output/alerts.json \
  --report output/incident_report.md
cat output/incident_report.md
```

Oczekiwany wynik: **3 syntetyczne alerty** z 8 rekordów: `ssh_bruteforce`, `ssh_success_after_bruteforce` i `guardian_remote_alert`. Nie oznacza to potwierdzonego ataku.

## Etap 3 — Wygeneruj klucz HMAC i zarejestruj kopię (BEZ ROOT)

```bash
umask 077
python3 -m vault new-key output/hmac.key
python3 -m vault seal \
  --log samples/remote.log \
  --key output/hmac.key \
  --ledger output/demo-ledger.json \
  --anchor output/demo-anchor.txt
python3 -m vault verify \
  --log samples/remote.log \
  --key output/hmac.key \
  --ledger output/demo-ledger.json \
  --anchor output/demo-anchor.txt
```

Wynik `VERIFIED ...` potwierdza, że aktualne dane odpowiadają rejestrowi i podanej kotwicy. W realnym wdrożeniu `--anchor` **musi wskazywać plik pobrany z zaufanego, niezależnego nośnika**, nie kopię przechowywaną razem z logiem.

## Etap 4 — Wykrywanie manipulacji logiem (BEZ ROOT)

Zmieniaj **wyłącznie kopię**, nigdy oryginalny materiał dowodowy:

```bash
cp samples/remote.log output/tampered.log
python3 - <<'PY'
from pathlib import Path
p = Path('output/tampered.log')
s = p.read_bytes()
assert s
p.write_bytes(b'X' + s[1:])
print('Zmieniono jeden bajt w syntetycznej kopii')
PY
python3 -m vault verify \
  --log output/tampered.log \
  --key output/hmac.key \
  --ledger output/demo-ledger.json \
  --anchor output/demo-anchor.txt
```

Oczekiwane: `EVIDENCE MISMATCH` i kod wyjścia **2**. Rozszerzenie tej wersji porównuje także niezależną kotwicę, co wykrywa podmianę logu i rejestru nawet przy znajomości klucza HMAC, o ile zaufana wcześniejsza kotwica pozostała poza kontrolą atakującego.

## Etap 5 — Wykonaj certyfikaty (TYLKO HOST C)

Przed wygenerowaniem certyfikatów zweryfikuj `openssl version` i przeczytaj skrypt:

```bash
openssl version
less scripts/make_lab_certs.sh
bash scripts/make_lab_certs.sh
```

Skrypt generuje:

- `pki/ca.crt` — publiczny certyfikat CA,
- `pki/ca.key` — **sekretny klucz CA, tylko na host C**,
- `pki/collector.crt`, `pki/collector.key` — dla kolektora `logs.lab`, EKU `serverAuth`,
- `pki/sender.crt`, `pki/sender.key` — dla nadawcy `mint-sender.lab`, EKU `clientAuth`.

Ważność wynosi **30 dni**, co jest dobre do laboratorium, ale wymaga rotacji przed upływem terminu. Zweryfikuj:

```bash
openssl verify -CAfile pki/ca.crt -purpose sslserver pki/collector.crt
openssl verify -CAfile pki/ca.crt -purpose sslclient pki/sender.crt
openssl x509 -in pki/collector.crt -noout -dates -ext subjectAltName
openssl x509 -in pki/sender.crt -noout -dates -ext subjectAltName
```

Nie przesyłaj CA KEY do hostów A/B. Nie zapisuj kluczy prywatnych w poleceniach wyświetlających ich treść.

## Etap 6 — Bezpiecznie przenieś certyfikaty z hosta C na hosty A i B

Na KAŻDYM hostcie A/B utwórz katalog `pki` w kopii projektu, jako zwykły użytkownik:

```bash
mkdir -p ~/linux-apt-evidence-vault/pki
chmod 700 ~/linux-apt-evidence-vault/pki
```

Na maszynie administracyjnej HOST C, w katalogu projektu, użyj SSH/SCP w prywatnej sieci albo VPN (podstaw rzeczywiste nazwy użytkowników i prywatne adresy):

```bash
# DO KOLEKTORA B
scp pki/ca.crt pki/collector.crt pki/collector.key \
  admin@KOLEKTOR_PRYWATNY_IP:~/linux-apt-evidence-vault/pki/

# DO NADAWCY A
scp pki/ca.crt pki/sender.crt pki/sender.key \
  mariusz@LAPTOP_PRYWATNY_IP:~/linux-apt-evidence-vault/pki/
```

Są to szablony wymagające podstawienia użytkowników i adresów. Zweryfikuj host key SSH przed przenoszeniem prywatnych kluczy. Po przesłaniu na hostach A/B wykonaj:

```bash
chmod 600 ~/linux-apt-evidence-vault/pki/*.key
chmod 644 ~/linux-apt-evidence-vault/pki/*.crt
```

## Etap 7 — Konfiguracja rsyslog na kolektorze (TYLKO HOST B)

Otwórz `configs/collector.conf`. Najważniejsze fragmenty:

```rsyslog
# TLS CA/cert/key (globalne parametry dla dedykowanego kolektora)
global(
    DefaultNetstreamDriverCAFile="/etc/rsyslog.d/vault-tls/ca.crt"
    DefaultNetstreamDriverCertFile="/etc/rsyslog.d/vault-tls/collector.crt"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/vault-tls/collector.key"
)
module(
    load="imtcp"
    StreamDriver.Name="gtls"
    StreamDriver.Mode="1"
    StreamDriver.AuthMode="x509/name"
    PermittedPeer=["mint-sender.lab"]
)
```

Pełna konfiguracja i `ruleset` zapisu do `/var/log/apt-vault/remote.log` znajdują się w repozytorium. Uwaga: logowy `host`, `tag` i `msg` mogą być sfałszowane przez skompromitowanego nadawcę; serwerowy `fromhost-ip` jest jedynie metadanymi połączenia, nie dowodem integralności źródła.

**Przed użyciem zapory przez SSH** dopuszczaj swoje aktualne połączenie administracyjne. Następnie ogranicz port 6514 do prawdziwego prywatnego IP nadawcy:

```bash
sudo ufw allow from NADAWCA_PRYWATNY_IP to any port 6514 proto tcp
sudo ufw status numbered
```

Na kolektorze:

```bash
cd ~/linux-apt-evidence-vault
less scripts/install_collector.sh
bash scripts/install_collector.sh
sudo rsyslogd -N1
sudo systemctl status rsyslog --no-pager
sudo ss -lntp | grep ':6514'
```

`rsyslogd -N1` musi zakończyć się pomyślnie. Jeżeli wystąpi błąd składni albo TLS — **nie kontynuuj** do momentu wyjaśnienia przyczyny.

## Etap 8 — Konfiguracja nadawcy na ThinkPadzie (TYLKO HOST A)

Adres `logs.lab` musi wskazywać prywatny IP kolektora; w lokalnej sieci możesz dodać go do `/etc/hosts` na nadawcy:

```bash
sudo nano /etc/hosts
```

Dodaj wiersz po podmianie adresu:

```text
KOLEKTOR_PRYWATNY_IP logs.lab
```

Sprawdź:

```bash
getent ahostsv4 logs.lab
```

Otwórz `configs/sender.conf`. Zwróć uwagę na:

```rsyslog
action(
    type="omfwd"
    target="logs.lab"
    port="6514"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="logs.lab"
    template="RSYSLOG_SyslogProtocol23Format"
    action.resumeRetryCount="-1"
    queue.type="LinkedList"
    queue.filename="apt-vault-fwd"
    queue.size="10000"
    queue.highWatermark="8000"
    queue.lowWatermark="2000"
    queue.maxDiskSpace="256m"
    queue.saveOnShutdown="on"
)
```

Konfiguracja przekazuje tylko `auth`, `authpriv`, `daemon`, `local5`; nie wysyła wszystkich prywatnych logów desktopu.

Na ThinkPadzie:

```bash
cd ~/linux-apt-evidence-vault
less scripts/install_sender.sh
bash scripts/install_sender.sh
sudo rsyslogd -N1
sudo systemctl status rsyslog --no-pager
```

Jeżeli w systemie jest niestandardowy rsyslog, inne globalne ustawienia certyfikatów mogą kolidować z laboratorium. `rsyslogd -N1` wykrywa błędy konfiguracji, ale nie zastępuje testu rzeczywistego połączenia.

## Etap 9 — Test end-to-end (A + B)

**Na nadawcy A:**

```bash
logger -p local5.notice -t apt-vault-test 'APT_VAULT_TEST_2026'
getent hosts logs.lab
openssl s_client -connect logs.lab:6514 -servername logs.lab \
  -verify_hostname logs.lab -CAfile pki/ca.crt \
  -cert pki/sender.crt -key pki/sender.key < /dev/null
```

**Na kolektorze B:**

```bash
sudo grep -F 'APT_VAULT_TEST_2026' /var/log/apt-vault/remote.log
sudo journalctl -u rsyslog -n 50 --no-pager
```

Przechwycony komunikat świadczy o dostarczeniu **jednego testowego zdarzenia**. `Verify return code: 0 (ok)` przy `openssl s_client` wskazuje na pomyślną weryfikację certyfikatu serwera, lecz nie potwierdza trwale działającego przepływu logów. Sprawdzaj oba warunki osobno.

## Etap 10 — Połącz z Projektem 4 na laptopie

```bash
python3 scripts/publish_guardian.py \
  --file ../linux-apt-defense-lab/output/demo/alerts.json \
  --dry-run

python3 scripts/publish_guardian.py \
  --file ../linux-apt-defense-lab/output/demo/alerts.json
```

Pierwsze polecenie wypisuje krótkie komunikaty `vault.alert={...}`; drugie wysyła je przez syslog z kategorią `local5`. Most wysyła tylko ID alertu i priorytet, bez pełnych danych użytkowników i IP. Powtarzane uruchomienie może wysłać ponownie już przesłane alerty — to ograniczenie demonstracji, rozwiązywane w przyszłości przez trwały stan offsetów/dedup.

## Etap 11 — Wykonaj prywatną kopię materiału dowodowego (TYLKO B)

```bash
umask 077
mkdir -p "$HOME/private-vault-cases/case001"
sudo test -f /var/log/apt-vault/remote.log
sudo cat /var/log/apt-vault/remote.log > \
  "$HOME/private-vault-cases/case001/remote.log"
chmod 600 "$HOME/private-vault-cases/case001/remote.log"
```

Nie wykonuj testów na żywym oryginalnym logu. Ogranicz uprawnienia katalogu do właściciela. Dla materiału o wysokiej wartości stosuj udokumentowany proces akwizycji, zaufany czas, kontrolę dostępu i kopię poza kolektorem.

## Etap 12 — Utwórz ledger i NIEZALEŻNĄ kotwicę (TYLKO B, a potem poza B)

```bash
mkdir -p "$HOME/private-vault-cases/case001/evidence"
python3 -m vault new-key \
  "$HOME/private-vault-cases/case001/evidence/hmac.key"
python3 -m vault seal \
  --log "$HOME/private-vault-cases/case001/remote.log" \
  --key "$HOME/private-vault-cases/case001/evidence/hmac.key" \
  --ledger "$HOME/private-vault-cases/case001/evidence/ledger.json" \
  --anchor "$HOME/private-vault-cases/case001/evidence/anchor.txt"
```

NATYCHMIAST skopiuj `anchor.txt` na offline/nośnik lub inny system chroniony oddzielnymi poświadczeniami. Nie polegaj wyłącznie na pliku `anchor.txt` obok logu. Aby sprawdzić integralność, **przywróć zaufaną kotwicę na czas weryfikacji** w innym katalogu i uruchom:

```bash
python3 -m vault verify \
  --log "$HOME/private-vault-cases/case001/remote.log" \
  --key "$HOME/private-vault-cases/case001/evidence/hmac.key" \
  --ledger "$HOME/private-vault-cases/case001/evidence/ledger.json" \
  --anchor "$HOME/private-vault-cases/case001/anchor-z-zaufanego-nosnika.txt"
```

Plik `anchor-z-zaufanego-nosnika.txt` jest celowo osobnym artefaktem; musi zostać niezależnie dostarczony. Weryfikacja nie potwierdza autentyczności treści logu sprzed jego odebrania.

## Etap 13 — Threat hunting kopii (TYLKO B)

```bash
python3 -m vault hunt \
  --log "$HOME/private-vault-cases/case001/remote.log" \
  --json output/case001-alerts.json \
  --report output/case001-report.md
cat output/case001-report.md
```

Silnik rozpoznaje: `ssh_bruteforce` (5 nieudanych prób SSH w 5 min, grupowanych host/IP), `ssh_success_after_bruteforce` oraz `guardian_remote_alert`. Nazwy hostów i pola zdarzeń pozostają niezaufane. Każdy alert wymaga analizy człowieka. Maksymalny rozmiar przetwarzanego pliku w laboratorium: 32 MiB.

## Etap 14 — Incident response i zabezpieczenie dowodów

1. Zweryfikuj czas na obu hostach i sprawdź ciągłość dostarczania logów.
2. Skopiuj materiał dowodowy poza zainfekowany host; zachowaj oryginały bez zmian.
3. Sprawdź `verify` z osobno przechowywaną kotwicą; zapisz wynik i identyfikator przypadku.
4. Porównaj zdarzenia SSH z rzeczywistą aktywnością administratorów, zmianami konfiguracji i alertami Projektu 4.
5. Jeżeli podejrzewasz aktywne włamanie, odizoluj źródło w sposób niewymazujący dowodów, po konsultacji z odpowiedzialnym administratorem.
6. Nie uruchamiaj komend sugerowanych w logach ani przez model AI. Decyzje o blokadach/odzyskiwaniu kont podejmuj ręcznie.

## Etap 15 — Rozwiązywanie problemów

**Brak połączenia:**

```bash
getent ahostsv4 logs.lab        # nadawca
nc -vz logs.lab 6514            # jeżeli netcat-openbsd zainstalowany
sudo journalctl -u rsyslog -n 80 --no-pager
sudo rsyslogd -N1
```

Na kolektorze sprawdź:

```bash
sudo ss -lntp | grep ':6514'
sudo ufw status numbered
sudo ls -ld /etc/rsyslog.d/vault-tls /var/log/apt-vault
sudo journalctl -u rsyslog -n 80 --no-pager
```

**Błąd TLS:** sprawdź ważność certyfikatów, SAN `logs.lab` / `mint-sender.lab`, CA, EKU i dostęp rsyslog do kluczy prywatnych. NIE przechodź na `AuthMode="anon"` i NIE wyłączaj weryfikacji certyfikatów.

**Brak logów po zerwaniu połączenia:** kolejka 256 MiB nie jest archiwum WORM. Zapełnienie lub awaria może powodować straty; monitoruj użycie dysku i restartuj usługi ostrożnie.

**Niezgodność SHA-256/HMAC:** zachowaj oryginały i porównaj z niezależną kotwicą; nie „naprawiaj” ledgeru poprzez ponowne zapieczętowanie w miejsce starego.

## Etap 16 — Cofnięcie zmian (ODDZIELNIE NA A I B)

```bash
cd ~/linux-apt-evidence-vault
less scripts/remove_vault.sh
bash scripts/remove_vault.sh
sudo rsyslogd -N1
sudo systemctl status rsyslog --no-pager
```

Na kolektorze usuń tylko wcześniej dodaną regułę UFW, jeżeli nie jest już potrzebna. Zobacz `sudo ufw status numbered` i usuń **konkretną właściwą regułę**, nie całą konfigurację. Skrypt celowo nie usuwa `/var/log/apt-vault/remote.log`, katalogów `private-vault-cases` ani innych dowodów. Zachowaj je zgodnie z planem retencji, a certyfikaty klienckie i serwerowe w projekcie `pki/` usuń lub zabezpiecz oddzielnie.

## Etap 17 — Co wrzucić na GitHub i jak opisać projekt

Umieść: `configs/*.conf`, `vault/*.py`, `scripts/*.sh`, testy, fikcyjne logi demo, instrukcję i screenshot **syntetycznego** raportu. Nigdy nie udostępniaj `pki/`, `*.key`, prawdziwych logów ani informacji o prywatnych hostach.

**Przykładowy opis:** `Built an mTLS-authenticated remote Linux logging laboratory using rsyslog, a bounded disk-assisted forwarding queue, Python-based SSH threat-hunting correlations, and SHA-256/HMAC evidence integrity verification with independently stored anchors. Added regression tests and documented incident-response and rollback procedures.`

## Kluczowe ograniczenia techniczne

- Wzajemny TLS chroni kanał i tożsamość certyfikatu, nie gwarantuje prawdziwości logów po kompromitacji nadawcy.
- Kotwica musi być **wcześniejsza** i **niezależnie przechowywana**; nadpisana/wyprodukowana na przejętym kolektorze jest bezwartościowa.
- Sam HMAC nie zapewnia niemożności usunięcia logów, nie chroni przed przerwaniem emisji zdarzeń i nie tworzy prawnie kompletnego łańcucha dowodowego.
- Projekt nie zastępuje WORM, oddzielnych kont adminów, bezpiecznych backupów, monitoringu pojemności, zbierania telemetryki jądra czy EDR.
- Plan zabezpieczenia przed APT powinien obejmować aktualizacje systemu, MFA, minimalne uprawnienia, izolację sieci i okresowe próby odtwarzania.

## Źródła techniczne

- https://docs.rsyslog.com/doc/configuration/modules/imtcp.html
- https://docs.rsyslog.com/doc/configuration/modules/omfwd.html
- https://docs.rsyslog.com/doc/concepts/ns_gtls.html
- https://docs.rsyslog.com/doc/concepts/queues.html
- https://docs.rsyslog.com/doc/rainerscript/queue_parameters.html
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/assembly_configuring-a-remote-logging-solution_security-hardening