# Maen Shield for Windows — UI Design

## Direction

The Windows interface is being rebuilt as an original security dashboard inspired by the clarity, hierarchy, and trust signals used by leading antivirus products. It does not copy Kaspersky's proprietary layout, assets, or identity.

## Visual system

| Element | Decision |
|---|---|
| Primary background | Soft blue-gray `#F4F7FB` |
| Sidebar | Deep navy `#0B1F33` |
| Primary accent | Shield blue `#1677D2` |
| Safe state | Green `#188A5B` |
| Review state | Amber `#C47A12` |
| Confirmed threat | Red `#C43D4B` |
| Cards | White, generous padding, subtle borders |
| Typography | Segoe UI, large status hierarchy, short labels |
| Direction | Arabic right-to-left or English left-to-right |

## Information architecture

The left navigation contains Overview, Scan, Quarantine, Updates, and Settings. The default Overview page answers three questions immediately: whether the device is protected, when the last scan occurred, and whether the intelligence database is current.

The main dashboard contains a prominent protection-status card, three quick actions, database and scan statistics, and a recent-results area. The Scan page exposes a large scan action, a selected path, progress, and findings. Quarantine, Updates, and Settings are represented as clear destinations even when their underlying functionality remains lightweight in the free edition.

## Acceptance criteria

The interface must no longer resemble a raw developer form. It must have a clear visual hierarchy, consistent spacing, readable status language, obvious primary actions, Arabic/English switching, and a conservative security state that does not claim protection when no verified intelligence database is installed.

The redesign must remain compatible with WinForms on .NET Framework 4.8 and Windows 7 SP1, avoid external UI packages, and keep the application lightweight.

## Functional mapping

| UI surface | Existing capability |
|---|---|
| Protection status | Verified intelligence database state |
| Smart scan | FileScanner over the user profile or selected path |
| Custom scan | Folder picker and target path |
| Update intelligence | CloudUpdateService with signed package verification |
| Results | Severity, path, reason, confidence |
| Updates card | Current manifest version and manual update action |
| Quarantine destination | Existing quarantine service / future navigation hook |
| Settings | Language selector and lightweight preferences |

## Product language

The interface uses calm, explicit wording: “Protected,” “Needs attention,” “Review recommended,” and “No verified database installed.” It avoids sensational claims and does not promise 100% protection.

Author: Manus AI

Status: implementation baseline

Generated: 2026-08-19
