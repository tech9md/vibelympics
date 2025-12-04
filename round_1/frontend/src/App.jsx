import { useState, useEffect, useMemo, Component } from 'react'
import { v4 as uuidv4 } from 'uuid'

// Error Boundary component for catching React errors
class ErrorBoundary extends Component {
  state = { hasError: false, error: null }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('React Error:', {
      error: error.message,
      stack: error.stack,
      componentStack: info.componentStack,
      timestamp: new Date().toISOString()
    })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <span className="error-icon">⚠️</span>
          <span className="error-text">Something went wrong</span>
          <button className="error-reload" onClick={() => window.location.reload()}>
            🔄 Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

export { ErrorBoundary }

// Emoji constants - the only "labels" in our app
const ROOM_TYPES = ['🛏️', '🛋️', '🍳', '🚿', '🏢', '🏠']
const TASKS = ['🧹', '🧽', '🛏️', '🪟', '🚽', '🗑️']
const STAFF_AVATARS = ['👤', '👩', '👨', '👩‍🦰', '👨‍🦱', '👩‍🦳', '👷', '🧑‍🔧']
const EMOJI_DIGITS = ['0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣']
const CELEBRATION_EMOJIS = ['🎉', '🎊', '✨', '⭐', '🌟', '💫', '🎯', '🏆']

// Configuration constants
const CELEBRATION_TIMEOUT_MS = 3000
const SAVE_DEBOUNCE_MS = 1000

// Generate request ID for correlation with backend logs
const generateRequestId = () =>
  `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

// Room-specific task mapping - bed task only for bedroom and house
const ROOM_TASKS = {
  '🛏️': ['🧹', '🧽', '🛏️', '🪟', '🚽', '🗑️'],  // Bedroom - all tasks
  '🛋️': ['🧹', '🧽', '🪟', '🚽', '🗑️'],         // Living Room - no bed
  '🍳': ['🧹', '🧽', '🪟', '🚽', '🗑️'],         // Kitchen - no bed
  '🚿': ['🧹', '🧽', '🪟', '🚽', '🗑️'],         // Bathroom - no bed
  '🏢': ['🧹', '🧽', '🪟', '🚽', '🗑️'],         // Office - no bed
  '🏠': ['🧹', '🧽', '🛏️', '🪟', '🚽', '🗑️'],  // House - all tasks
}
const STATUS_CYCLE = ['❌', '⏳', '✅']
const PRIORITY = ['🟢', '🟡', '🔴']

// Helper functions
const formatNumberAsEmoji = (num) => {
  return String(num).split('').map(d => EMOJI_DIGITS[parseInt(d)]).join('')
}

const isValidRoom = (room) => {
  return room &&
    typeof room === 'object' &&
    typeof room.type === 'string' &&
    typeof room.tasks === 'object'
}

const getOverallStatus = (room) => {
  const statuses = Object.values(room.tasks)
  if (statuses.every(s => s === '✅')) return '🟢'
  if (statuses.some(s => s === '⏳')) return '🟡'
  if (statuses.every(s => s === '❌')) return '🔴'
  return '🟡'
}

function App() {
  const [rooms, setRooms] = useState([])
  const [showAddRoom, setShowAddRoom] = useState(false)
  const [selectedRoomType, setSelectedRoomType] = useState(ROOM_TYPES[0])
  const [filter, setFilter] = useState(null)
  const [staffFilter, setStaffFilter] = useState(null)
  const [celebrating, setCelebrating] = useState(null)
  const [isOffline, setIsOffline] = useState(false)

  // Migrate room data to only include applicable tasks for room type and add assignedTo
  const migrateRoom = (room) => {
    if (!isValidRoom(room)) {
      console.warn('Invalid room data, skipping:', room)
      return null
    }
    const applicableTasks = ROOM_TASKS[room.type] || TASKS
    const migratedTasks = {}
    applicableTasks.forEach(task => {
      migratedTasks[task] = room.tasks?.[task] || '❌'
    })
    return {
      ...room,
      tasks: migratedTasks,
      assignedTo: room.assignedTo || '👤'
    }
  }

  // Load rooms from API on mount
  useEffect(() => {
    const requestId = generateRequestId()
    fetch('/api/rooms', {
      headers: { 'x-request-id': requestId }
    })
      .then(res => res.json())
      .then(data => {
        const migrated = data.map(migrateRoom).filter(Boolean)
        setRooms(migrated)
        setIsOffline(false)
      })
      .catch((error) => {
        console.error('API Error:', {
          endpoint: '/api/rooms',
          action: 'load',
          error: error.message,
          requestId,
          timestamp: new Date().toISOString()
        })
        setIsOffline(true)
        try {
          const saved = localStorage.getItem('emoji-rooms')
          if (saved) {
            const parsed = JSON.parse(saved)
            const migrated = parsed.map(migrateRoom).filter(Boolean)
            setRooms(migrated)
          }
        } catch (localError) {
          console.error('Failed to load from localStorage:', localError)
        }
      })
  }, [])

  // Debounced save to API
  useEffect(() => {
    if (rooms.length === 0) return

    const timeoutId = setTimeout(() => {
      const requestId = generateRequestId()
      fetch('/api/rooms', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-request-id': requestId
        },
        body: JSON.stringify(rooms)
      })
        .then(res => {
          if (res.ok) {
            setIsOffline(false)
          }
          return res.json()
        })
        .catch((error) => {
          console.error('API Error:', {
            endpoint: '/api/rooms',
            action: 'save',
            error: error.message,
            roomCount: rooms.length,
            requestId,
            timestamp: new Date().toISOString()
          })
          setIsOffline(true)
          localStorage.setItem('emoji-rooms', JSON.stringify(rooms))
        })
    }, SAVE_DEBOUNCE_MS)

    return () => clearTimeout(timeoutId)
  }, [rooms])

  // Auto-clear celebrations
  useEffect(() => {
    if (celebrating) {
      const timer = setTimeout(() => setCelebrating(null), CELEBRATION_TIMEOUT_MS)
      return () => clearTimeout(timer)
    }
  }, [celebrating])

  // Generic field update helper for DRY code
  const updateRoomField = (roomId, field, options) => {
    setRooms(rooms.map(room => {
      if (room.id === roomId) {
        const currentIndex = options.indexOf(room[field])
        const nextIndex = (currentIndex + 1) % options.length
        return { ...room, [field]: options[nextIndex] }
      }
      return room
    }))
  }

  const addRoom = () => {
    const newRoom = {
      id: uuidv4(),
      type: selectedRoomType,
      number: rooms.filter(r => r.type === selectedRoomType).length + 1,
      tasks: ROOM_TASKS[selectedRoomType].reduce((acc, task) => ({ ...acc, [task]: '❌' }), {}),
      priority: '🟢',
      assignedTo: '👤',
      lastUpdated: new Date().toISOString()
    }
    setRooms([...rooms, newRoom])
    setShowAddRoom(false)
  }

  const cycleTaskStatus = (roomId, task) => {
    setRooms(prevRooms => {
      const newRooms = prevRooms.map(room => {
        if (room.id === roomId) {
          const currentIndex = STATUS_CYCLE.indexOf(room.tasks[task])
          const nextIndex = (currentIndex + 1) % STATUS_CYCLE.length
          return {
            ...room,
            tasks: { ...room.tasks, [task]: STATUS_CYCLE[nextIndex] },
            lastUpdated: new Date().toISOString()
          }
        }
        return room
      })

      // Check for celebrations
      const updatedRoom = newRooms.find(r => r.id === roomId)
      const wasComplete = prevRooms.find(r => r.id === roomId)
      const isNowComplete = Object.values(updatedRoom.tasks).every(s => s === '✅')
      const wasNotComplete = !Object.values(wasComplete.tasks).every(s => s === '✅')

      if (isNowComplete && wasNotComplete) {
        const allComplete = newRooms.every(r => Object.values(r.tasks).every(s => s === '✅'))
        setCelebrating(allComplete ? 'all' : roomId)
      }

      return newRooms
    })
  }

  const cyclePriority = (roomId) => updateRoomField(roomId, 'priority', PRIORITY)
  const cycleStaffAssignment = (roomId) => updateRoomField(roomId, 'assignedTo', STAFF_AVATARS)

  const deleteRoom = (roomId) => {
    setRooms(rooms.filter(room => room.id !== roomId))
  }

  const resetRoom = (roomId) => {
    setRooms(rooms.map(room => {
      if (room.id === roomId) {
        return {
          ...room,
          tasks: ROOM_TASKS[room.type].reduce((acc, task) => ({ ...acc, [task]: '❌' }), {}),
          lastUpdated: new Date().toISOString()
        }
      }
      return room
    }))
  }

  // Memoized calculations for performance
  const filteredRooms = useMemo(() => {
    return rooms.filter(room => {
      const statusMatch = !filter || getOverallStatus(room) === filter
      const staffMatch = !staffFilter || room.assignedTo === staffFilter
      return statusMatch && staffMatch
    })
  }, [rooms, filter, staffFilter])

  const stats = useMemo(() => {
    const result = { total: 0, done: 0, inProgress: 0, pending: 0 }
    rooms.forEach(room => {
      const status = getOverallStatus(room)
      result.total++
      if (status === '🟢') result.done++
      else if (status === '🟡') result.inProgress++
      else if (status === '🔴') result.pending++
    })
    return result
  }, [rooms])

  const staffWithRooms = useMemo(() => {
    const staffMap = new Map()
    rooms.forEach(room => {
      staffMap.set(room.assignedTo, (staffMap.get(room.assignedTo) || 0) + 1)
    })
    return STAFF_AVATARS
      .filter(staff => staffMap.has(staff))
      .map(staff => ({ avatar: staff, count: staffMap.get(staff) }))
  }, [rooms])

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="logo" aria-label="Emoji Housekeeping Board">🏠✨</div>
        {isOffline && (
          <span
            className="offline-indicator"
            aria-label="Offline mode - using local storage"
            title="Offline mode - using local storage"
          >
            📴
          </span>
        )}
        <div className="stats" role="toolbar" aria-label="Filter options">
          <span
            className="stat"
            onClick={() => setFilter(null)}
            data-active={filter === null}
            role="button"
            aria-label="Show all rooms"
            aria-pressed={filter === null}
          >
            📊 {rooms.length > 0 && <span className="stat-num">{stats.total}</span>}
          </span>
          <span
            className="stat"
            onClick={() => setFilter('🟢')}
            data-active={filter === '🟢'}
            role="button"
            aria-label="Show completed rooms"
            aria-pressed={filter === '🟢'}
          >
            🟢 {stats.done > 0 && <span className="stat-num">{stats.done}</span>}
          </span>
          <span
            className="stat"
            onClick={() => setFilter('🟡')}
            data-active={filter === '🟡'}
            role="button"
            aria-label="Show in-progress rooms"
            aria-pressed={filter === '🟡'}
          >
            🟡 {stats.inProgress > 0 && <span className="stat-num">{stats.inProgress}</span>}
          </span>
          <span
            className="stat"
            onClick={() => setFilter('🔴')}
            data-active={filter === '🔴'}
            role="button"
            aria-label="Show pending rooms"
            aria-pressed={filter === '🔴'}
          >
            🔴 {stats.pending > 0 && <span className="stat-num">{stats.pending}</span>}
          </span>
          {staffWithRooms.length > 0 && <span className="stat-divider" aria-hidden="true">|</span>}
          {staffWithRooms.map(({ avatar, count }) => (
            <span
              key={avatar}
              className="stat staff-stat"
              onClick={() => setStaffFilter(staffFilter === avatar ? null : avatar)}
              data-active={staffFilter === avatar}
              role="button"
              aria-label={`Filter by staff ${avatar}`}
              aria-pressed={staffFilter === avatar}
            >
              {avatar} <span className="stat-num">{count}</span>
            </span>
          ))}
        </div>
        <button
          className="add-btn"
          onClick={() => setShowAddRoom(true)}
          aria-label="Add new room"
        >
          ➕
        </button>
      </header>

      {/* Task Legend */}
      <div className="legend" role="list" aria-label="Task types legend">
        {TASKS.map(task => (
          <span key={task} className="legend-item" role="listitem">{task}</span>
        ))}
      </div>

      {/* Room Grid */}
      <div className="room-grid" role="list" aria-label="Rooms">
        {filteredRooms.map(room => (
          <div
            key={room.id}
            className={`room-card ${celebrating === room.id ? 'celebrating' : ''}`}
            data-status={getOverallStatus(room)}
            role="listitem"
            aria-label={`Room ${room.type} ${room.number}`}
          >
            <div className="room-header">
              <span className="room-id">
                {room.type}
                <span className="room-number">
                  {formatNumberAsEmoji(room.number)}
                </span>
              </span>
              <span
                className="staff-assignment"
                onClick={() => cycleStaffAssignment(room.id)}
                role="button"
                aria-label="Change staff assignment"
              >
                {room.assignedTo}
              </span>
              <span
                className="room-status"
                onClick={() => cyclePriority(room.id)}
                role="button"
                aria-label="Change priority"
              >
                {room.priority}
              </span>
              <span className="overall-status" aria-label="Overall status">
                {getOverallStatus(room)}
              </span>
            </div>

            <div className="task-grid" role="group" aria-label="Tasks">
              {ROOM_TASKS[room.type].map(task => (
                <button
                  key={task}
                  className="task-btn"
                  data-status={room.tasks[task]}
                  onClick={() => cycleTaskStatus(room.id, task)}
                  aria-label={`Task ${task}, status: ${room.tasks[task]}`}
                  aria-pressed={room.tasks[task] === '✅'}
                >
                  <span className="task-icon">{task}</span>
                  <span className="task-status">{room.tasks[task]}</span>
                </button>
              ))}
            </div>

            <div className="room-actions">
              <button
                className="action-btn"
                onClick={() => resetRoom(room.id)}
                aria-label="Reset all tasks in this room"
              >
                🔄
              </button>
              <button
                className="action-btn delete"
                onClick={() => deleteRoom(room.id)}
                aria-label="Delete this room"
              >
                🗑️
              </button>
            </div>
          </div>
        ))}

        {filteredRooms.length === 0 && (
          <div className="empty-state" role="status" aria-label="No rooms found">
            {filter ? (
              <>
                <span className="empty-icon">🔍</span>
                <span className="empty-filter">{filter}</span>
                <span className="empty-icon">❌</span>
              </>
            ) : (
              <>
                <span className="empty-icon">🏠</span>
                <span className="empty-icon">➕</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Add Room Modal */}
      {showAddRoom && (
        <div
          className="modal-overlay"
          onClick={() => setShowAddRoom(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Add new room"
        >
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <span>🏠</span>
              <span>➕</span>
            </div>
            <div className="room-type-selector" role="radiogroup" aria-label="Select room type">
              {ROOM_TYPES.map(type => (
                <button
                  key={type}
                  className={`type-btn ${selectedRoomType === type ? 'selected' : ''}`}
                  onClick={() => setSelectedRoomType(type)}
                  role="radio"
                  aria-checked={selectedRoomType === type}
                  aria-label={`Room type ${type}`}
                >
                  {type}
                </button>
              ))}
            </div>
            <div className="modal-actions">
              <button
                className="modal-btn cancel"
                onClick={() => setShowAddRoom(false)}
                aria-label="Cancel"
              >
                ❌
              </button>
              <button
                className="modal-btn confirm"
                onClick={addRoom}
                aria-label="Confirm add room"
              >
                ✅
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Celebration Overlay */}
      {celebrating === 'all' && (
        <div
          className="celebration-overlay"
          onClick={() => setCelebrating(null)}
          role="dialog"
          aria-label="Celebration! All rooms complete!"
        >
          <div className="confetti-container" aria-hidden="true">
            {CELEBRATION_EMOJIS.map((emoji, i) => (
              <span
                key={emoji}
                className="confetti"
                style={{
                  left: `${10 + (i * 12)}%`,
                  animationDelay: `${i * 0.1}s`
                }}
              >
                {emoji}
              </span>
            ))}
          </div>
          <div className="celebration-message">
            <span className="celebration-emoji">🏆</span>
            <span className="celebration-emoji">✨</span>
            <span className="celebration-emoji">🎉</span>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
