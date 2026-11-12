# BQ25882 board-photo comparison

Reviewed 2026-11-12, using public spare-board photographs and the original
C1.70 EX image identified in [RESEARCH.md](RESEARCH.md). No camera communication,
disassembly, measurement, or firmware modification was performed.

**Result: the firmware favors BQ25882, but no photographed package is identified
as that part.** The photos support a size-compatible inspection target and
several exclusions. They do not expose the required electrical connections.

[Download the annotated viewer](board-map.html) and open it in a browser. It
loads original seller images from their CDN, with separate coordinate overlays;
the repository does not redistribute the photographs. A saved original can
also be selected locally for offline viewing. Source dimensions, URLs and
SHA-256 fingerprints are embedded in the viewer. No reconstructed lettering,
sharpening or generative enhancement was used.

## Package and circuit constraints

TI's [BQ25882 datasheet](https://www.tij.co.jp/jp/lit/ds/symlink/bq25882.pdf),
§6, §9.2, §11 and drawing YFF0025, specifies a 25-ball DSBGA, nominally
2.1 × 2.1 mm; body limits are 2.075–2.135 mm, ball pitch 0.4 mm. The package
addendum lists `BQ25882` as the part marking. Tape-cavity dimensions are not
body dimensions. Its example circuit uses a 1 µH inductor between PMID and SW,
with nearby input, SYS and BAT capacitors. Layout proximity matters, but Nikon
need not reproduce TI's component arrangement or example values.

The older USB-side photo reads `STM32F412 / ZEJ6`. ST specifies
[STM32F412ZEJ6](https://www.st.com/en/microcontrollers-microprocessors/stm32f412ze.html)
as **UFBGA144, 10 × 10 mm**, rather than the 7 mm package of another variant.
Its photographed outline is roughly 115–120 pixels per side. Thus a BQ25882
body should be only about **24–26 pixels** on that photograph. This is a rough
scale check, not metrology: perspective, edge selection and image compression
limit accuracy. Corresponding positions on the newer board are matched by
component arrangement, not proof that both boards have the same revision/BOM.

## Located areas

Coordinates are `(x, y, width, height)` in the unrotated source image, origin
at top left. Labels below are research labels, **not Nikon designators**.
Boxes include a small margin and are not measured package outlines.

| Label | New USB side, 1600 × 1024 | Older USB side, 1200 × 1600 | Assessment |
| --- | --- | --- | --- |
| M | `(632,378,125,127)` | `(633,667,123,126)` | STM32 position; readable identity on the older photo, layout correspondence on the newer one. Scale reference, not the charger. |
| P1 | `(1246,668,29,30)` | `(445,1321,33,34)` | Small IC near the port-side power components. Approximate body scale is compatible with 2.1 mm. **Weak inspection target only:** no readable BQ marking, no confirmed 25-ball package, no identified SW/PMID connection. Visible edge features cannot establish its package type. |
| P2 | `(1153,642,45,43)` | `(451,1218,49,49)` | Larger IC next to a light rectangular two-terminal component and capacitors. Roughly 3–4 mm at the MCU scale; a poorer BQ25882 fit. The light component has not been established as an inductor. |
| X1 | `(1141,737,67,65)` | `(328,1209,72,81)` | Large IC with an apparent `D65190` marking, adjacent to the conspicuous copper-wound component. About 5–6 mm, incompatible with a normal 2.1 mm BQ25882 package. Its exact identity/function is not established here. |
| D | Separate DC-board contact side: `(428,445,212,161)` | — | Sticker-covered components remain unresolved. The component-side photo also lacks readable part markings. This board cannot be eliminated as the charger location. |

P1 ranks ahead of P2 **only by visible package scale**. It is not a positive
charger identification. A conspicuous coil does not by itself identify its
controller, and matching capacitor colors/counts does not establish a net.
No visible continuous route was established from any candidate to both the
required inductor terminals and the MCU's I²C pins. Buried layers, BGA escape
routing, occlusion and unresolved component markings prevent that conclusion.
The SD-side image was also reviewed; its other power clusters do not provide
a unique BQ25882 match. This is a bounded photo review, not an exhaustive
inventory of every component.

## AliExpress gallery originals

The supplied [listing 1005010161490916](https://aliexpress.ru/item/1005010161490916.html)
was examined on 2026-11-12. The Russian page presented an access check. A public
international page response, redirected to `ar.aliexpress.com`, exposed five
original JPEG URLs in `imagePathList`. All five unsuffixed files decoded as
**800 × 800**, with no larger gallery source found in that response. This is
not proof that the seller has no larger photographs elsewhere.

| Gallery position | Direct original | Observed view |
| --- | --- | --- |
| 1 | [S5db425…](https://ae-pic-a1.aliexpress-media.com/kf/S5db425e62d4842d48e12aa8ecf2a6013g.jpg) | SD side with Z6 II cover label |
| 2 | [S51199d…](https://ae-pic-a1.aliexpress-media.com/kf/S51199d32321d4f448ca1cfc7d1b96c1aj.jpg) | Straight-on USB side, matching the user's first USB-side attachment |
| 3 | [Sd14148…](https://ae-pic-a1.aliexpress-media.com/kf/Sd141487f49c04840a5216e9dd0918003u.jpg) | Additional straight-on USB view; separate source, not an enlarged copy of position2 |
| 4 | [S641122…](https://ae-pic-a1.aliexpress-media.com/kf/S64112284d4284a3fbf99888fe04bd0bbC.jpg) | Oblique USB view, matching the user's second USB-side attachment |
| 5 | [S4af158…](https://ae-pic-a1.aliexpress-media.com/kf/S4af1586f3a06498a8b0399004cb3b8d6Z.jpg) | Oblique SD view |

The gallery watermark reads **Camera Parts Global Store**. The card and cover
describe Z6 II; this is seller attribution. Apparent silk suffixes in positions2
and3 are `13-01 A7` and `12-01 A7`; their meaning is not established. These views
must not be assumed to show one physical specimen or an identical revision.

The [viewer](board-map.html) now includes these five originals and their SHA-256
fingerprints. P1/P2/M/X1 are mapped onto the two straight-on USB views by
surrounding component arrangement. P1 is only roughly a dozen pixels across:
neither the BQ25882 marking nor its ball pattern can be established. The new
angle does not establish inductor or I²C continuity. The chip-location and POR
conclusions remain unchanged. No larger image was synthesized or inferred
from a requested display size; no firmware code or hardware was changed.

## Firmware constraints on a future physical identification

The existing EX trace fixes I²C1 on **PB8/PB9 AF4**, addressing 7-bit `0x6B`.
Under the BQ25882 pinout, SCL is D2 and SDA is E2. Photos cannot show continuity
under either BGA. PE0 and PC9 require more caution:

| Static code observation | What follows |
| --- | --- |
| `0802B218(0)` clears PC9; a nonzero argument sets it, through `08043ADA`. | Establishes GPIO polarity, not the destination pin. |
| `0802B40C(r0=0)` sets PC9 HIGH before I²C; a nonzero argument sets LOW. Normal builder `08028D10` also sets config byte9 to1, transferred to register06 bit3. | Normal path combines PC9 HIGH with EN_CHG=1. A direct connection to active-low CE is **not established**; inversion, a different function, or other gating remains possible. |
| Field `region1+117` entering5 calls `B40C(1)`; leaving5 calls `B234`, which clears PC9 after successful I²C. | Both examined transitions can leave PC9 LOW. This is not an entry/exit toggle that proves restoration. Ordinary service-exit mode1 does not invoke this callback. |
| `0802ACF0` reads PE0 without inversion. `08029924` collects ten samples at `2001FC8C..95`. The gated classifier at `08029998..BA`, `080299E4..EA` stores all-LOW=0, all-HIGH=1, mixed=2 at `2000ED9D`. | Shows stable/mixed-input classification. It does not prove a blink frequency, a STAT wire, PG, INT, or a particular fault meaning. |

TI defines CE as active-low, PG as active-low power-good, and INT as an
active-low 256 µs pulse. **BQ25882 has no STAT pin**; BQ25883 does. Thus a
STAT interpretation of PE0 cannot confirm BQ25882 and would require another
device/variant or a different explanation. Filtering an unstable PG signal is
also possible. The register11 bit3 discriminator remains the stronger
firmware evidence for82; shared-driver code remains an alternative.

The initialization at `0802B170` configures PC9 as output but does not itself
write its level. That is insufficient to assert an initial LOW after every
kind of restart. These additional observations are static disassembly; they
do not add to the published emulation-test count.

## What would resolve the location

Existing attributable macro photos showing P1 and the DC-board components,
with readable markings and board revision, would be useful contributions.
An existing schematic/boardview or documented continuity result tying SCL/SDA
and the PMID–inductor–SW path to the same IC would be stronger than proximity.
Do not treat this map as a request to dismantle or power a camera.

Nothing in these photos proves loss of BAT/VBUS power, discharge time, or
recovery after a broken service session. The prior conditional POR conclusion
is unchanged. Submit source links and counterevidence through
[Issues](https://github.com/Findefor/Z6ModKit/issues) or
[Discussions](https://github.com/Findefor/Z6ModKit/discussions).
