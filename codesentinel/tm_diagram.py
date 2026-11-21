"""Threat-model data-flow diagram (Qt graphics) - used by the editable page and to render the report image."""
from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path

from PySide6.QtCore import QLineF, QPointF, QRectF, Qt, Signal, QObject
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF, QImage
from PySide6.QtWidgets import (QGraphicsItem, QGraphicsPathItem, QGraphicsRectItem, QGraphicsScene,
                               QGraphicsSimpleTextItem, QGraphicsTextItem)

from .threatmodel import ThreatModel

W, H = 190, 62
STYLE = {   # kind -> (fill, border, label)
    "actor": ("#F2F4F7", "#344054", "External entity"),
    "entry": ("#E8F1FB", "#1F3A5F", "Entry point"),
    "process": ("#FFFFFF", "#1F3A5F", "Process"),
    "store": ("#FFF8E1", "#B08800", "Data store"),
    "service": ("#F4F0FF", "#7048E8", "External service"),
    "infra": ("#ECFDF3", "#2B8A3E", "Deployment"),
}
ZONES = {"internet": ("Internet - untrusted", "#B42318"), "device": ("User device - untrusted", "#D9480F"),
         "app": ("Application - trusted", "#1F3A5F"), "data": ("Data - internal", "#B08800"),
         "third-party": ("Third parties", "#7048E8")}


class Bus(QObject):
    moved = Signal()
    picked = Signal(str)            # element id
    edit = Signal(str)


class NodeItem(QGraphicsItem):
    def __init__(self, el, bus: Bus, open_findings: int):
        super().__init__()
        self.el, self.bus, self.n = el, bus, open_findings
        self.edges: list["EdgeItem"] = []
        self.setFlags(QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemIsSelectable |
                      QGraphicsItem.ItemSendsGeometryChanges)
        self.setPos(el.x, el.y)
        self.setZValue(2)
        self.setToolTip(f"{STYLE.get(el.kind, ('', '', el.kind))[2]}: {el.name}\n{el.details}\n"
                        + "\n".join(el.evidence[:6]))

    def boundingRect(self):
        return QRectF(-4, -12, W + 18, H + 16)

    def paint(self, p: QPainter, opt, widget=None):
        fill, border, _ = STYLE.get(self.el.kind, STYLE["process"])
        pen = QPen(QColor(border), 2.4 if self.isSelected() else 1.4)
        if self.el.kind == "service":
            pen.setStyle(Qt.DashLine)
        p.setPen(pen)
        p.setBrush(QColor(fill))
        r = QRectF(0, 0, W, H)
        k = self.el.kind
        if k == "process":
            p.drawRoundedRect(r, 28, 28)
        elif k == "entry":
            p.drawRoundedRect(r, 10, 10)
        elif k == "store":
            p.setPen(Qt.NoPen); p.drawRect(r); p.setPen(pen)
            p.drawLine(r.topLeft(), r.topRight()); p.drawLine(r.bottomLeft(), r.bottomRight())
            p.drawLine(QPointF(14, 0), QPointF(14, H))
        else:
            p.drawRect(r)
        p.setPen(QColor("#101828"))
        f = QFont(); f.setPointSize(8); f.setBold(True); p.setFont(f)
        p.drawText(r.adjusted(18 if k == "store" else 8, 4, -6, -18), Qt.AlignCenter | Qt.TextWordWrap, self.el.name)
        f.setBold(False); f.setPointSize(7); p.setFont(f); p.setPen(QColor("#667085"))
        p.drawText(r.adjusted(6, H - 18, -6, -2), Qt.AlignCenter, STYLE.get(k, ("", "", k))[2]
                   + (" · edited" if self.el.manual else ""))
        if self.n:
            p.setBrush(QColor("#B42318")); p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(W - 12, -10, 24, 20))
            p.setPen(QColor("white")); f.setBold(True); p.setFont(f)
            p.drawText(QRectF(W - 12, -10, 24, 20), Qt.AlignCenter, str(self.n))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            self.el.x, self.el.y = self.pos().x(), self.pos().y()
            for e in self.edges:
                e.adjust()
        if change == QGraphicsItem.ItemSelectedHasChanged and value:
            self.bus.picked.emit(self.el.id)
        return super().itemChange(change, value)

    def mouseReleaseEvent(self, ev):
        super().mouseReleaseEvent(ev)
        self.bus.moved.emit()

    def mouseDoubleClickEvent(self, ev):
        self.bus.edit.emit(self.el.id)

    def anchor(self, toward: QPointF) -> QPointF:
        c = self.pos() + QPointF(W / 2, H / 2)
        d = toward - c
        if d.x() == 0 and d.y() == 0:
            return c
        sx = (W / 2) / abs(d.x()) if d.x() else math.inf
        sy = (H / 2) / abs(d.y()) if d.y() else math.inf
        return c + d * min(sx, sy)


class EdgeItem(QGraphicsPathItem):
    def __init__(self, flow, a: NodeItem, b: NodeItem):
        super().__init__()
        self.flow, self.a, self.b = flow, a, b
        a.edges.append(self); b.edges.append(self)
        color = QColor("#B42318" if flow.crosses else "#475467")
        pen = QPen(color, 1.3)
        if flow.manual:
            pen.setStyle(Qt.DashDotLine)
        self.setPen(pen)
        self.setZValue(1)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.label = QGraphicsSimpleTextItem(flow.label, self)
        f = QFont(); f.setPointSize(7); self.label.setFont(f)
        self.label.setBrush(color)
        self.setToolTip(f"Data flow: {flow.label}" + (" (crosses a trust boundary)" if flow.crosses else ""))
        self.adjust()

    def adjust(self):
        ca = self.a.pos() + QPointF(W / 2, H / 2)
        cb = self.b.pos() + QPointF(W / 2, H / 2)
        p1, p2 = self.a.anchor(cb), self.b.anchor(ca)
        path = QPainterPath(p1)
        path.lineTo(p2)
        line = QLineF(p2, p1)
        ang = math.radians(line.angle())
        size = 8
        left = p2 + QPointF(math.cos(ang + math.pi / 7) * size, -math.sin(ang + math.pi / 7) * size)
        right = p2 + QPointF(math.cos(ang - math.pi / 7) * size, -math.sin(ang - math.pi / 7) * size)
        path.addPolygon(QPolygonF([p2, left, right, p2]))
        self.setPath(path)
        mid = (p1 + p2) / 2
        self.label.setPos(mid + QPointF(4, -12))


def build_scene(tm: ThreatModel, finding_counts: dict[str, int] | None = None, bus: Bus | None = None
                ) -> tuple[QGraphicsScene, dict, list]:
    """finding_counts: element id -> number of threats with findings."""
    bus = bus or Bus()
    scene = QGraphicsScene()
    scene.setBackgroundBrush(QColor("#FFFFFF"))
    counts = finding_counts or {}
    nodes = {}
    for e in tm.elements:
        n = NodeItem(e, bus, counts.get(e.id, 0))
        scene.addItem(n)
        nodes[e.id] = n
    edges = []
    for f in tm.flows:
        if f.src in nodes and f.dst in nodes and f.src != f.dst:
            ed = EdgeItem(f, nodes[f.src], nodes[f.dst])
            scene.addItem(ed)
            edges.append(ed)
    zones = draw_zones(scene, tm)
    for n in nodes.values():
        n.zones = zones
    return scene, nodes, edges


def draw_zones(scene: QGraphicsScene, tm: ThreatModel) -> list:
    """Dashed trust-boundary boxes around the elements of each zone."""
    for it in [i for i in scene.items() if getattr(i, "is_zone", False)]:
        scene.removeItem(it)
    boxes = defaultdict(list)
    for e in tm.elements:
        boxes[e.zone].append(QRectF(e.x, e.y, W, H))
    out = []
    for zone, rects in boxes.items():
        r = rects[0]
        for x in rects[1:]:
            r = r.united(x)
        r = r.adjusted(-16, -34, 16, 14)
        label, color = ZONES.get(zone, (zone, "#667085"))
        pen = QPen(QColor(color), 1.2, Qt.DashLine)
        box = QGraphicsRectItem(r)
        box.setPen(pen)
        box.setBrush(Qt.NoBrush)
        box.setZValue(0)
        box.is_zone = True
        t = QGraphicsSimpleTextItem(label, box)
        f = QFont(); f.setPointSize(8); f.setBold(True); t.setFont(f)
        t.setBrush(QColor(color))
        t.setPos(r.left() + 6, r.top() + 4)
        scene.addItem(box)
        out.append(box)
    return out


def render_png(tm: ThreatModel, path: str | Path, finding_counts: dict | None = None, scale: float = 1.6) -> Path:
    """Draw the diagram to a PNG (needs a QApplication - the caller creates one)."""
    scene, *_ = build_scene(tm, finding_counts)
    rect = scene.itemsBoundingRect().adjusted(-20, -20, 20, 20)
    img = QImage(int(rect.width() * scale), int(rect.height() * scale), QImage.Format_ARGB32)
    img.fill(QColor("white"))
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.TextAntialiasing)
    scene.render(p, QRectF(img.rect()), rect)
    p.end()
    img.save(str(path))
    return Path(path)


def finding_counts(tm: ThreatModel) -> dict:
    c = defaultdict(int)
    for t in tm.threats:
        if t.status == "Finding exists":
            c[t.element] += 1
    return dict(c)
