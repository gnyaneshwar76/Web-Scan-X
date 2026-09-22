---
name: webscanx-drive-stitch-directly
description: "WebScanX design work — drive Stitch via MCP myself, review my own output, don't hand the user prompts to paste"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 2002ab0a-1ae0-4c24-b16b-a6d7e69839f8
  modified: 2026-09-15T09:34:02.993Z
---

For WebScanX (E:\WebScanX), the user wants me to connect to Stitch (MCP, project 136720474880128415) and make/edit/review the designs myself instead of writing prompts for them to paste and asking them to "see once".

**Why:** the paste → "see once" → review loop wasted their time; they said "use your potential", and will grant any access I ask for.

**How to apply:** use edit_screens / generate_screen_from_text, then self-review (download screenshot, slice, grep copy) and iterate until it passes before reporting. Stitch has no delete-screen tool — ask the user to delete duplicates by hand. Edits on a whole long page can break rendering; keep edit prompts small and re-check. Related: [[rideconnectx-decide-dont-ask]].
