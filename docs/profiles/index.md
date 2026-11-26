# Profiles

Each page describes one published [profile](../how/profiles-machines.md): the firmware it covers, its guests, the OEM inputs the user imports and the commands that prepare a machine. OEM inputs are never part of Voyemu; the user imports them from firmware they have.

| Profile | Android | Multimedia | Cluster |
| --- | --- | --- | --- |
| [free-09-chinese-20260106-6.0.3](free-09-chinese-20260106-6.0.3.md) | 9 | Supported | Supported |
| [free-11-chinese-20250710-6.11.1](free-11-chinese-20250710-6.11.1.md) | 11 | Supported | Supported |
| [free-11-chinese-20260731-7.3.1](free-11-chinese-20260731-7.3.1.md) | 11 | Supported | Supported |
| [free-11-russian-20260318-rc1](free-11-russian-20260318-rc1.md) | 11 | Experimental | None |
| [free-09-chinese-20221230-nxp-rc45](free-09-chinese-20221230-nxp-rc45.md) | 9 | Supported | None |
| [passion-11-russian-20260403-2.1.4.80](passion-11-russian-20260403-2.1.4.80.md) | 11 | Supported | Experimental |

A profile name gives the vehicle line, the Android generation, the firmware language, the firmware date and its version. Every profile runs the multimedia on two screens of 1920×720 and draws its own steering wheel in the [window](../how/window.md).

Preparation of any profile follows the [common procedure](../how/preparation.md): `deps PROFILE`, then `fetch` with the input route of the profile, then `build`.
