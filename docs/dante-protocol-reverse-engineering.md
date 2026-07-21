# Dante AES67 – Reverse Engineering der Empfangs-Seite (RX)

Analyse der Capture `Dante.pcapng` (875 Pakete). Ziel: das Kommando finden, mit dem
Dante Controller ein Dante-Gerät dazu bringt, einen **AES67-Flow zu empfangen**.

## Setup in der Capture

| Rolle | Adresse | Bemerkung |
|-------|---------|-----------|
| Dante Controller (Software) | `192.168.97.100`, Quellport `64445` | schickt die Steuerkommandos |
| **Ziel-Gerät (Empfänger)** | `192.168.97.101` | unser Gerät |
| weitere Geräte | `.196`, `192.168.99.93` | im Netz sichtbar |
| PTP-Grandmaster / Clock | `192.168.99.1` | 542 Pakete, v.a. PTP (319/320) |

Beobachtete Ports: **319/320** (PTP), **8700/8702/8708** (ConMon-Status, Multicast an
224.0.0.23x), **4440** (ARC / Audio-Control – hier laufen die Kommandos), **5353** (mDNS).

Wichtig: **Kein SAP-Traffic (Port 9875)** und **keine 239.x-AES67-Multicast-Adressen**
in der Capture. Das ist also die **Dante-interne AES67-Steuerung** über das proprietäre
Control-Protokoll — nicht der SAP/SDP-Weg, über den ein *Fremd*-AES67-Sender entdeckt würde.

## Protokoll-Framing (bestätigt, wie netaudio-Core)

Alle Kommandos auf Port 4440 folgen dem `protocol_packet`-Layout:

```
Offset  Feld
0:2     Protokoll-ID   (0x2809 = AES67-Config, Antworten teils 0x2801)
2:4     Länge (Bytes gesamt)
4:6     Transaction-ID (pro Request hochgezählt)
6:8     Opcode
8:10    0x0000 (Trenner)
10:     Body
```

## Die RX-relevanten Opcodes (ctrl -> Gerät, Port 4440)

| Opcode | Länge | Rolle |
|--------|-------|-------|
| `0x3410` | 28 B | **Flow-Bindung** (einmalig): bindet den Flow an einen Ziel-Dante-RX-Kanal. Nur in Capture 2 (neue Flow-Anlage). |
| `0x3201` | 112 B | **Quellkanal mappen** (je Aufruf): legt einen Quell-Stream-Kanal in den Flow. |
| `0x3400` | 34 B | Kanal-Info abfragen (Antwort enthält Kanalnamen `Ch 1` / `CH1`) |
| `0x3600` | 34 B | RX-Status/Flow-Liste abfragen (Polling) |

### Beweis aus Capture 2 (`dante2.pcapng`)

Sechs `0x3201`-Kommandos, **Byte 102 = 1,2,3,4,5,6** = exakt die sechs gerouteten
Stream-Quellkanäle. Davor genau **ein** `0x3410` mit Zielfeld `0001` = Dante-RX-Kanal 1.
Damit ist Byte 102 eindeutig der **Quellkanal im Stream** (nicht der Zielkanal).

Die `0x3xxx`-Range ist die Empfänger-Seite (vgl. netaudio: `0x3001` RX-Kanalname,
`0x3010/0x3014` Subscription add/remove). `0x3201` unter Protokoll `0x2809` ist damit
konsistent die **AES67-Empfangs-Konfiguration**.

## Feldkarte Opcode `0x3201` (112 Byte)

> **Korrektur (Dante3.pcapng, 2026-07-16):** Die ursprüngliche Annahme, Offset 102
> sei der Ziel-RX-Kanal, war falsch. **Offset 102 = Quell-Stream-Kanal.** Der
> **Ziel-Dante-RX-Kanal** steht in **zwei** Feldern: `@96:98` (Kanalnummer direkt)
> und `@52:54` (Begleitwert). Byte-genau bestätigt: Kanal 1 → (`@52:54`=0x0002,
> `@96:98`=0x0001), Kanal 2 → (0x0008, 0x0002). Der Bug „nur Kanal 1 geschaltet"
> kam daher, dass beide Zielfelder ungepatcht auf Kanal 1 blieben.

Diff der frühen Captures (#509, #681, #794): dort änderte sich nur Transaction-ID
und Offset 102 — weil alle denselben Ziel-Kanal hatten und nur der Quellkanal
variierte.

```
Offset  Bytes           Bedeutung (bestätigt / vermutet)
  0:2   2809            Protokoll AES67-Config          [bestätigt]
  2:4   0070            Länge 112                        [bestätigt]
  4:6   00xx            Transaction-ID                   [bestätigt]
  6:8   3201            Opcode                           [bestätigt]
 8:10   0000            Trenner                          [bestätigt]
   16   4202            ? Flow-/Format-Kennung           [vermutet]
 52:54  00 02 / 00 08   Ziel-Dante-Kanal (Begleitwert)   [BESTÄTIGT ch1/ch2; >2 extrapoliert]
   68   c0 a8 01 64     Source-IP 192.168.1.100 (Sender, unicast)  [BESTÄTIGT]
   76   0001e240        0x1E240 (=123456) Session-/Stream-Feld     [offen]
 96:98  00 01 / 00 02   >> ZIEL-Dante-RX-Kanal <<                   [BESTÄTIGT via Dante3]
  102   01..06          >> QUELL-Stream-Kanal <<                    [BESTÄTIGT: 1..6]
  106   13 8c           RTP-Port 5004                               [BESTÄTIGT]
  108   ef 01 01 01     Multicast 239.1.1.1                         [BESTÄTIGT]

### Opcode 0x3410 (Flow-Bindung, 28 B)

```
    4:6   Transaction-ID                              [BESTÄTIGT]
   16     08            Flow-Slot / -ID?              [offen]
   20:22  00 01         Ziel-Dante-RX-Kanal (=1)      [HYPOTHESE, passt zu "auf dante ch1"]
   22:24  00 03         ?                             [offen]
```
```

Hex der ersten Instanz (#509):
```
280900700020 3201 0000 010100100000000042020000000000000000000100000000
0068000000000000000000030040000000000002006000000000000000001000000b
c0a80164 000000000001e240 00000000000000000000000000000000 0001 0002 000001 00
0802138cef 010101
```

## Was gesichert ist vs. was noch fehlt

**Gesichert:**
- Empfangs-Steuerung läuft über Protokoll `0x2809`, Port 4440.
- `0x3201` ist der schreibende RX-Konfig-Befehl; `0x3400`/`0x3600` sind Abfragen.
- Offset 102 ist der Kanal-/Slot-Selektor (variierte 1→2).
- Framing identisch zum bereits offengelegten netaudio-Schema.

**Noch nicht gesichert (nur eine Flow-Konfiguration in der Capture):**
**Per bekannter Flow-Parameter bestätigt** (Source 192.168.1.100 / Multicast 239.1.1.1 /
Port 5004): Source-IP @68, RX-Kanal @102, RTP-Port @106, Multicast @108. Der Builder
reproduziert das Originalpaket damit byte-genau.

**Noch offen:**
- Bedeutung von Offset 76 (`0001e240`) und der `4202`-Kennung @16 (bleiben im Builder
  als Template-Werte erhalten).
- Ob `0x3201` einen Flow **anlegt** oder eine bestehende **Subscription referenziert**,
  und ob die `0x3600`/`0x3400`-Queries zwingend vorausgeschickt werden müssen.
- Verhalten bei >255 Kanälen (Feld @102 ist 1 Byte).

## Nächster Schritt: gezielte Captures zum Festnageln

Um die Feld-Semantik zu bestätigen, jeweils **eine Variable ändern** und mitschneiden
(Wireshark-Filter: `udp.port==4440 || udp.port==8700 || udp.port==9875`):

1. **RX-Kanal variieren:** denselben Flow einmal auf RX-Kanal 1, einmal auf 3, einmal 8
   abonnieren. -> bestätigt Offset 102 (und ob weitere Bytes mitwandern).
2. **Multicast-Adresse variieren:** zwei Flows mit unterschiedlichen, dir bekannten
   AES67-Multicast-Adressen empfangen. -> lokalisiert das Adressfeld eindeutig.
3. **Fremd-Sender testen:** wenn ein Nicht-Dante-AES67-Sender empfangen werden soll,
   eine Capture *inkl. Port 9875 (SAP)* machen — dann sehen wir, ob Dante zusätzlich
   über SDP/SAP geht (anderer Pfad als hier).

Schick die neuen `.pcapng` — ich diffe sie und baue daraus den bestätigten
Python-Kommando-Builder für `0x3201` (analog `build_create_tx_flow`).

## AES67 Multicast Prefix (per Gerät) — bestätigt via prefix_l.pcap (2026-07-16)

Der AES67-Multicast-Bereich eines Geräts ist `239.<prefix>.x.x`. Aus einem
Dante-Controller-Mitschnitt (Prefix 69 → 99 → 69):

**Schreiben — Opcode `0x1101` (20 B):**
```
2809 0014 <txid> 1101 0000 0101 8060 0010 ef PP 0000
                                              └ @17 = Prefix (0x45=69, 0x63=99); @16=0xEF (239)
```
Antwort (RESP) spiegelt das Paket mit @9: 00→01.

**Lesen — Opcode `0x1100` Info-Query:**
Request `2809003e00df1100…00660214` (62 B). Die Antwort endet auf
`… ef PP 00 00 00 1e 84 80`; der Prefix ist das Byte bei `len-7`, abgesichert
über `resp[-8]==0xEF` und Trailer `resp[-3:]==1e8480`. Getestet für
Antwortlängen 148 und 156.

Builder/Parser: `dante.build_set_aes67_prefix`, `read_aes67_prefix`,
`set_aes67_prefix`, `parse_aes67_prefix`. Schreiben geht direkt aufs Geraet (immer live).

## AES67 Multicast TX Flow anlegen — bestätigt via tx_ch.pcap (2026-07-16)

Opcode `0x2601` (CREATE_TX_FLOW, AES67). Kontrollierte Captures (AVIO USB,
alle mit Multicast 239.69.236.153:5004): CH1, CH2, CH1+2.

**1-Kanal-Flow (112 B):** Quell-TX-Kanal @96:98, Port @106:108, Multicast @108:112.
CH1 und CH2 unterscheiden sich in genau einem Byte (@97) — alle Zähl-/Längenfelder
sind identisch.

**2-Kanal-Flow (116 B):** Kanal-IDs @96:98 und @98:100, Port @110:112,
Multicast @112:116. Die internen Zählfelder (Länge @89, @22, 0a15, 040b, 0507)
haengen nur von der Kanal-ANZAHL ab, nicht von den Kanal-Werten — daher genuegt
das Patchen von Kanal-IDs + Multicast + Port (byte-exakt getestet).

Builder: `dante.build_create_tx_flow(channels, multicast, port)` /
`create_tx_flow(...)`. >2 Kanaele brauchen weitere Captures.

## Multicast TX Flow loeschen — bestaetigt via delete_flow_neutrik.pcapng (2026-07-21)

Flow-Management laeuft fuer ALLE Geraete ueber classic proto `0x2801`: `0x2200`
Flow-Summary, `0x2204` Flow-SDP, `0x2202` Delete. Delete-Request (16 B):
`2801 0010 <txid> 2202 0000 0001 <flowid:4>` — Flow-ID @12:16. Geraete-ACK:
`2801 000a <txid> 2202 0001 …` (0x0001 @8:10 = OK). Die Flow-ID steht auch im
SDP-Session-Namen `s=Name : <flowid>`; `0x2204` je Slot 1..N liefert die SDP,
sodass die Flow-ID einer Multicast direkt am Geraet (ohne SAP) ermittelbar ist.
Builder: `dante.build_delete_tx_flow`, `delete_tx_flow`, `find_flow_id`. Der angelegte Flow wird vom Geraet per SAP announced und taucht damit
automatisch als NMOS-Sender auf.


## RX-Kanal unsubscriben — bestaetigt via unsubscribe_avio.pcapng (2026-07-21)

Der Unsubscribe eines Dante-RX-Kanals ist der **0x3410-Bind allein**, ohne
folgende 0x3201-Map. Im Capture (AVIO, Kanal 1+2 unsubscribed) gibt es KEIN
einziges 0x3201; die einzigen Aktions-Requests sind zwei 0x3410-Binds, byte-
identisch zum Subscribe-Bind. Danach faellt die Subscription-Status-Query
(0x3600) von 144 B (mit Multicast/Quelle) auf 22 B leer. Der Bind leert also den
Kanal; im Subscribe weist die nachfolgende Map die Quelle zu. Geraete-ACK:
`2809 0014 <txid> 3410 0001 …`. Builder: `dante.build_clear_channel` (==
`build_bind`), `clear_subscription`; verdrahtet in `ReceiverManager._deactivate`.
