// Generates the YogaFP app icon (an original fingerprint drawing, no SF Symbols) as an .iconset.
//   swift make_icon.swift <output.iconset>
// Big Sur-style rounded square, deep blue gradient, white fingerprint ridges forming a whorl.
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func render(_ px: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px)
    let ctx = NSGraphicsContext.current!.cgContext

    // macOS icon grid: the shape sits inside ~80% of the canvas, corner radius ~22.5% of the shape.
    let inset = s * 0.1
    let tile = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let shape = CGPath(roundedRect: tile, cornerWidth: tile.width * 0.225, cornerHeight: tile.width * 0.225, transform: nil)

    // soft drop shadow
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.012), blur: s * 0.03, color: NSColor(white: 0, alpha: 0.35).cgColor)
    ctx.addPath(shape); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
    ctx.restoreGState()

    // gradient background
    ctx.saveGState()
    ctx.addPath(shape); ctx.clip()
    let colors = [NSColor(calibratedRed: 0.10, green: 0.42, blue: 0.95, alpha: 1).cgColor,
                  NSColor(calibratedRed: 0.03, green: 0.16, blue: 0.48, alpha: 1).cgColor] as CFArray
    let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])!
    ctx.drawLinearGradient(grad, start: CGPoint(x: tile.minX, y: tile.maxY), end: CGPoint(x: tile.maxX, y: tile.minY), options: [])
    // subtle top highlight
    let hl = [NSColor(white: 1, alpha: 0.18).cgColor, NSColor(white: 1, alpha: 0).cgColor] as CFArray
    let hgrad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: hl, locations: [0, 1])!
    ctx.drawLinearGradient(hgrad, start: CGPoint(x: 0, y: tile.maxY), end: CGPoint(x: 0, y: tile.midY), options: [])

    // fingerprint: nested, slightly offset elliptical ridges with irregular gaps (deterministic)
    let cx = tile.midX, cy = tile.midY - tile.height * 0.03
    let lw = max(1.0, tile.width * 0.026)
    ctx.setLineWidth(lw)
    ctx.setLineCap(.round)
    ctx.setStrokeColor(NSColor(white: 1, alpha: 0.95).cgColor)
    let rings = 8
    for i in 0..<rings {
        let r = tile.width * (0.05 + 0.039 * CGFloat(i))
        let rx = r, ry = r * 1.24
        let ox = CGFloat(i) * tile.width * 0.004          // ridges drift a little, like a real whorl
        // each ridge is drawn as 1-2 arcs with a gap; angles in degrees, 0 = right, counter-clockwise
        let starts: [CGFloat] = [-60, -45, -75, -30, -55, -80, -40, -65]
        let lens:   [CGFloat] = [300, 320, 285, 330, 300, 270, 315, 290]
        let a0 = starts[i % starts.count], a1 = a0 + lens[i % lens.count]
        let split = i % 3 == 1 ? a0 + (a1 - a0) * 0.55 : nil   // some ridges break in the middle
        func arc(_ from: CGFloat, _ to: CGFloat) {
            let path = CGMutablePath()
            var first = true
            var a = from
            while a <= to {
                let t = a * .pi / 180
                let p = CGPoint(x: cx + ox + rx * cos(t), y: cy + ry * sin(t))
                if first { path.move(to: p); first = false } else { path.addLine(to: p) }
                a += 2
            }
            ctx.addPath(path); ctx.strokePath()
        }
        if let m = split { arc(a0, m - 12); arc(m + 12, a1) } else { arc(a0, a1) }
    }
    ctx.restoreGState()
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

let sizes: [(String, Int)] = [("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64),
                              ("128x128", 128), ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512),
                              ("512x512", 512), ("512x512@2x", 1024)]
for (name, px) in sizes {
    let data = render(px).representation(using: .png, properties: [:])!
    try! data.write(to: URL(fileURLWithPath: "\(out)/icon_\(name).png"))
}
print("wrote \(out)")
