export type XY = { x: number; y: number };

export type WH = { width: number; height: number };

export type Line = { from: XY; to: XY };

export type XYWH = XY & WH;
