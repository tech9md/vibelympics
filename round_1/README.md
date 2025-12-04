# 🏠✨ Emoji Housekeeping Board

A **fully emoji-only** housekeeping status board for hotels, Airbnbs, offices, and cleaning services. No text in any interactive elements - just pure emoji communication that transcends language barriers.

## 🎯 What It Does

This is a real-world task tracking board where cleaning staff can:

- ➕ Add rooms/areas by type (🛏️ bedroom, 🛋️ living room, 🍳 kitchen, etc.)
- 🔄 Track task completion by tapping to cycle status (❌ → ⏳ → ✅)
- 👥 Assign rooms to staff members by tapping avatar icons
- 📊 Filter by status or staff member
- 🎉 Celebrate completions with animations
- 🎨 All without reading a single word

### Task Types
| 🧹 | 🧽 | 🛏️ | 🪟 | 🚽 | 🗑️ |
|:---:|:---:|:---:|:---:|:---:|:---:|
| Sweep | Scrub | Make Bed | Windows | Toilet | Trash |

> **Smart Tasks**: Tasks are context-aware based on room type. The 🛏️ (Make Bed) task only appears for bedrooms and whole-house cleaning. All other tasks appear for all room types.

### Status Flow
```
❌ (Not started) → ⏳ (In progress) → ✅ (Complete)
```

### Room Status
```
🔴 All tasks pending
🟡 Some tasks in progress
🟢 All tasks complete
```

### Staff Avatars
| 👤 | 👩 | 👨 | 👩‍🦰 | 👨‍🦱 | 👩‍🦳 | 👷 | 🧑‍🔧 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Unassigned | Staff 1 | Staff 2 | Staff 3 | Staff 4 | Staff 5 | Staff 6 | Staff 7 |

> Tap the avatar in any room card to cycle through staff. Staff with assigned rooms appear in the header for quick filtering.

## 🐳 Running with Docker (Chainguard)

### Build the container
```bash
docker build -t emoji-housekeeping .
```

### Run locally
```bash
docker run -p 3000:3000 emoji-housekeeping
```

Then open **http://localhost:3000** in your browser.

### With persistent data (optional)
To persist data across container restarts, you can mount a local file:
```bash
# Create local data file
echo "[]" > data.json

# Run with volume mount
docker run -p 3000:3000 -v $(pwd)/data.json:/app/backend/data.json emoji-housekeeping
```

## 🛠️ Local Development (without Docker)

### Prerequisites
- Node.js 18+
- npm

### Install dependencies
```bash
npm run install:all
```

### Run in development mode
```bash
npm run dev
```

Frontend runs on http://localhost:5173
Backend API runs on http://localhost:3000

### Build for production
```bash
npm run build
npm start
```

## 🏗️ Project Structure

```
emoji-housekeeping/
├── frontend/          # React + Vite frontend
│   ├── src/
│   │   ├── App.jsx    # Main app component
│   │   ├── main.jsx   # React entry point
│   │   └── index.css  # Styles
│   └── ...
├── backend/           # Express API server
│   └── server.js
├── Dockerfile         # Chainguard container config
└── README.md
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rooms` | GET | 📋 Get all rooms |
| `/api/rooms` | POST | 💾 Save room data |
| `/api/health` | GET | ✅ Health check |

## 📱 Features

- **📱 Mobile-friendly** - Touch-optimized for tablets and phones
- **🌐 Universal** - Works across all languages
- **⚡ Fast** - Lightweight and responsive
- **💾 Persistent** - Data survives container restarts
- **🎨 Dark mode** - Easy on the eyes in any lighting
- **🧠 Smart tasks** - Context-aware tasks based on room type
- **👥 Staff assignment** - Assign and filter rooms by team member
- **🎉 Celebrations** - Animated feedback when tasks/rooms complete

## 🤔 Why Emoji-Only?

1. **🌍 Language barriers** - Cleaning crews are often multilingual
2. **⏱️ Speed** - Tap, don't type
3. **👀 Glanceability** - Status visible from across the room
4. **🎯 Reduced errors** - No typos, no misunderstandings

## 📜 License

MIT

---

Built for the Vibelympics 🏆 Vibe Coding Challenge
