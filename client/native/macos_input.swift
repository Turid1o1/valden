import AppKit
import CoreGraphics
import Foundation

func fail(_ message: String) -> Never {
  if let data = "\(message)\n".data(using: .utf8) {
    FileHandle.standardError.write(data)
  }
  exit(1)
}

func parseDouble(_ raw: String, _ name: String) -> Double {
  guard let value = Double(raw), value.isFinite else {
    fail("invalid \(name): \(raw)")
  }
  return value
}

func parseInt(_ raw: String, _ name: String) -> Int {
  guard let value = Int(raw) else {
    fail("invalid \(name): \(raw)")
  }
  return value
}

func clamp(_ value: Double, _ minValue: Double, _ maxValue: Double) -> Double {
  return max(minValue, min(maxValue, value))
}

func currentMousePoint() -> CGPoint {
  return NSEvent.mouseLocation
}

func mouseEventType(button: CGMouseButton, down: Bool) -> CGEventType {
  switch button {
    case .left:
      return down ? .leftMouseDown : .leftMouseUp
    case .right:
      return down ? .rightMouseDown : .rightMouseUp
    default:
      return down ? .otherMouseDown : .otherMouseUp
  }
}

func parseMouseButton(_ raw: String) -> CGMouseButton {
  switch raw.lowercased() {
    case "left":
      return .left
    case "right":
      return .right
    case "middle", "center":
      return .center
    default:
      fail("unsupported mouse button: \(raw)")
  }
}

func postMouseMoveNormalized(xNorm: Double, yNorm: Double) {
  let displayBounds = CGDisplayBounds(CGMainDisplayID())
  let x = displayBounds.origin.x + displayBounds.width * clamp(xNorm, 0, 1)
  let y = displayBounds.origin.y + displayBounds.height * (1 - clamp(yNorm, 0, 1))
  let point = CGPoint(x: x, y: y)

  guard let event = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point, mouseButton: .left) else {
    fail("failed to create mouse move event")
  }
  event.post(tap: .cghidEventTap)
}

func postMouseButton(button: CGMouseButton, down: Bool) {
  guard let event = CGEvent(
    mouseEventSource: nil,
    mouseType: mouseEventType(button: button, down: down),
    mouseCursorPosition: currentMousePoint(),
    mouseButton: button
  ) else {
    fail("failed to create mouse button event")
  }
  event.post(tap: .cghidEventTap)
}

func postMouseClick(button: CGMouseButton) {
  postMouseButton(button: button, down: true)
  postMouseButton(button: button, down: false)
}

func postMouseScroll(dx: Int, dy: Int) {
  guard let event = CGEvent(
    scrollWheelEvent2Source: nil,
    units: .pixel,
    wheelCount: 2,
    wheel1: Int32(-dy),
    wheel2: Int32(dx),
    wheel3: 0
  ) else {
    fail("failed to create scroll event")
  }
  event.post(tap: .cghidEventTap)
}

let keyCodes: [String: CGKeyCode] = [
  "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6, "x": 7, "c": 8, "v": 9, "b": 11,
  "q": 12, "w": 13, "e": 14, "r": 15, "y": 16, "t": 17, "1": 18, "2": 19, "3": 20, "4": 21,
  "6": 22, "5": 23, "=": 24, "9": 25, "7": 26, "-": 27, "8": 28, "0": 29, "]": 30, "o": 31,
  "u": 32, "[": 33, "i": 34, "p": 35, "l": 37, "j": 38, "'": 39, "k": 40, ";": 41, "\\": 42,
  ",": 43, "/": 44, "n": 45, "m": 46, ".": 47, "`": 50,
  "return": 36, "enter": 36, "tab": 48, "space": 49, "backspace": 51, "delete": 51,
  "escape": 53, "esc": 53, "command": 55, "meta": 55, "shift": 56, "capslock": 57, "option": 58,
  "alt": 58, "control": 59, "ctrl": 59, "rightshift": 60, "rightoption": 61, "rightalt": 61,
  "rightcontrol": 62, "rightctrl": 62, "fn": 63,
  "f1": 122, "f2": 120, "f3": 99, "f4": 118, "f5": 96, "f6": 97, "f7": 98, "f8": 100, "f9": 101,
  "f10": 109, "f11": 103, "f12": 111,
  "arrowleft": 123, "arrowright": 124, "arrowdown": 125, "arrowup": 126,
  "home": 115, "end": 119, "pageup": 116, "pagedown": 121
]

func postKeyEvent(key: String, down: Bool) {
  guard let code = keyCodes[key.lowercased()] else {
    fail("unsupported key: \(key)")
  }
  guard let event = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: down) else {
    fail("failed to create key event")
  }
  event.post(tap: .cghidEventTap)
}

func postTextInput(_ text: String) {
  if text.isEmpty {
    return
  }

  let utf16 = Array(text.utf16)
  guard !utf16.isEmpty else {
    return
  }

  guard let keyDown = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true) else {
    fail("failed to create key down event for text")
  }
  keyDown.keyboardSetUnicodeString(stringLength: utf16.count, unicodeString: utf16)
  keyDown.post(tap: .cghidEventTap)

  guard let keyUp = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false) else {
    fail("failed to create key up event for text")
  }
  keyUp.keyboardSetUnicodeString(stringLength: utf16.count, unicodeString: utf16)
  keyUp.post(tap: .cghidEventTap)
}

func usage() -> Never {
  fail("usage: valden-input <move-norm|mouse-down|mouse-up|mouse-click|mouse-scroll|key-down|key-up|text> ...")
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
  usage()
}

switch command {
  case "move-norm":
    guard args.count == 3 else { usage() }
    let xNorm = parseDouble(args[1], "xNorm")
    let yNorm = parseDouble(args[2], "yNorm")
    postMouseMoveNormalized(xNorm: xNorm, yNorm: yNorm)

  case "mouse-down":
    guard args.count == 2 else { usage() }
    postMouseButton(button: parseMouseButton(args[1]), down: true)

  case "mouse-up":
    guard args.count == 2 else { usage() }
    postMouseButton(button: parseMouseButton(args[1]), down: false)

  case "mouse-click":
    guard args.count == 2 else { usage() }
    postMouseClick(button: parseMouseButton(args[1]))

  case "mouse-scroll":
    guard args.count == 3 else { usage() }
    let dx = parseInt(args[1], "dx")
    let dy = parseInt(args[2], "dy")
    postMouseScroll(dx: dx, dy: dy)

  case "key-down":
    guard args.count == 2 else { usage() }
    postKeyEvent(key: args[1], down: true)

  case "key-up":
    guard args.count == 2 else { usage() }
    postKeyEvent(key: args[1], down: false)

  case "text":
    guard args.count == 2 else { usage() }
    postTextInput(args[1])

  default:
    usage()
}
