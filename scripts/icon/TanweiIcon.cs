// Tanwei Console app icon generator (GDI+): renders build/icon.png + multi-size build/icon.ico.
// Design: dark rounded tile + cyan radar (outer/inner ring, sweep) + amber contact blip.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

public static class TanweiIcon
{
    static GraphicsPath Rounded(float x, float y, float w, float h, float r)
    {
        GraphicsPath p = new GraphicsPath();
        float d = r * 2f;
        p.AddArc(x, y, d, d, 180, 90);
        p.AddArc(x + w - d, y, d, d, 270, 90);
        p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
        p.AddArc(x, y + h - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    static Bitmap Master()
    {
        Bitmap bmp = new Bitmap(1024, 1024, PixelFormat.Format32bppArgb);
        Graphics g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.Clear(Color.Transparent);

        Color cyan = Color.FromArgb(255, 52, 229, 200);
        Color cyanLight = Color.FromArgb(255, 125, 247, 224);
        Color cyanMid = Color.FromArgb(255, 60, 231, 202);
        Color cyanDeep = Color.FromArgb(255, 24, 179, 156);
        Color amber = Color.FromArgb(255, 245, 181, 68);

        GraphicsPath tile = Rounded(0, 0, 1024, 1024, 224);
        LinearGradientBrush bg = new LinearGradientBrush(
            new RectangleF(0, 0, 1024, 1024),
            Color.FromArgb(255, 14, 30, 42), Color.FromArgb(255, 4, 8, 13), 45f);
        ColorBlend bgBlend = new ColorBlend(3);
        bgBlend.Colors = new Color[]
        {
            Color.FromArgb(255, 14, 30, 42),
            Color.FromArgb(255, 8, 17, 25),
            Color.FromArgb(255, 4, 8, 13)
        };
        bgBlend.Positions = new float[] { 0f, 0.55f, 1f };
        bg.InterpolationColors = bgBlend;
        g.FillPath(bg, tile);
        g.SetClip(tile);

        // Sweep wedge, -45 deg to 0 deg
        GraphicsPath sweepPath = new GraphicsPath();
        double c = Math.Cos(Math.PI / 4);
        sweepPath.AddPolygon(new PointF[]
        {
            new PointF(512f, 512f),
            new PointF((float)(512 + 316 * c), (float)(512 - 316 * c)),
            new PointF(828f, 512f)
        });
        try
        {
            PathGradientBrush sweep = new PathGradientBrush(sweepPath);
            sweep.CenterColor = Color.FromArgb(74, 52, 229, 200);
            sweep.SurroundColors = new Color[] { Color.FromArgb(0, 52, 229, 200) };
            g.FillPath(sweep, sweepPath);
            sweep.Dispose();
        }
        catch
        {
            SolidBrush sb = new SolidBrush(Color.FromArgb(22, 52, 229, 200));
            g.FillPath(sb, sweepPath);
            sb.Dispose();
        }

        // Outer ring with gradient stroke
        LinearGradientBrush ringBrush = new LinearGradientBrush(
            new RectangleF(232, 232, 560, 560), cyanLight, cyanDeep, 45f);
        ColorBlend ringBlend = new ColorBlend(3);
        ringBlend.Colors = new Color[] { cyanLight, cyanMid, cyanDeep };
        ringBlend.Positions = new float[] { 0f, 0.5f, 1f };
        ringBrush.InterpolationColors = ringBlend;
        Pen ringPen = new Pen(ringBrush, 56f);
        ringPen.StartCap = LineCap.Round;
        ringPen.EndCap = LineCap.Round;
        g.DrawEllipse(ringPen, 232f, 232f, 560f, 560f);

        // Inner ring
        Pen innerPen = new Pen(Color.FromArgb(235, 60, 231, 202), 36f);
        g.DrawEllipse(innerPen, 364f, 364f, 296f, 296f);
        innerPen.Dispose();

        // Sweep line
        Pen sweepPen = new Pen(cyanLight, 44f);
        sweepPen.StartCap = LineCap.Round;
        sweepPen.EndCap = LineCap.Round;
        g.DrawLine(sweepPen, 512f, 512f, 712f, 312f);
        sweepPen.Dispose();

        // Amber arc accent riding on the outer ring
        Pen amberPen = new Pen(amber, 56f);
        amberPen.StartCap = LineCap.Round;
        amberPen.EndCap = LineCap.Round;
        g.DrawArc(amberPen, 232f, 232f, 560f, 560f, 138f, 34f);
        amberPen.Dispose();

        // Contact blips
        SolidBrush centerBrush = new SolidBrush(Color.FromArgb(255, 139, 255, 232));
        g.FillEllipse(centerBrush, 474f, 474f, 76f, 76f);
        centerBrush.Dispose();
        SolidBrush amberBrush = new SolidBrush(amber);
        g.FillEllipse(amberBrush, 642f, 606f, 60f, 60f);
        amberBrush.Dispose();
        SolidBrush blipBrush = new SolidBrush(Color.FromArgb(215, 52, 229, 200));
        g.FillEllipse(blipBrush, 370f, 382f, 44f, 44f);
        blipBrush.Dispose();

        g.ResetClip();

        // Inner border
        GraphicsPath edgePath = Rounded(8, 8, 1008, 1008, 216);
        LinearGradientBrush edgeBrush = new LinearGradientBrush(
            new RectangleF(8, 8, 1008, 1008),
            Color.FromArgb(226, 43, 85, 102), Color.FromArgb(226, 43, 85, 102), 45f);
        ColorBlend edgeBlend = new ColorBlend(3);
        edgeBlend.Colors = new Color[]
        {
            Color.FromArgb(226, 43, 85, 102),
            Color.FromArgb(150, 22, 50, 63),
            Color.FromArgb(226, 43, 85, 102)
        };
        edgeBlend.Positions = new float[] { 0f, 0.5f, 1f };
        edgeBrush.InterpolationColors = edgeBlend;
        Pen edgePen = new Pen(edgeBrush, 14f);
        g.DrawPath(edgePen, edgePath);
        edgePen.Dispose();
        edgeBrush.Dispose();
        edgePath.Dispose();
        ringPen.Dispose();
        ringBrush.Dispose();
        sweepPath.Dispose();
        bg.Dispose();
        tile.Dispose();
        g.Dispose();
        return bmp;
    }

    static Bitmap Resize(Bitmap src, int size)
    {
        Bitmap d = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        Graphics g = Graphics.FromImage(d);
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.CompositingMode = CompositingMode.SourceCopy;
        ImageAttributes ia = new ImageAttributes();
        ia.SetWrapMode(WrapMode.TileFlipXY);
        g.DrawImage(src, new Rectangle(0, 0, size, size), 0, 0, src.Width, src.Height, GraphicsUnit.Pixel, ia);
        ia.Dispose();
        g.Dispose();
        return d;
    }

    static byte[] DibBytes(Bitmap b)
    {
        int size = b.Width;
        BitmapData data = b.LockBits(new Rectangle(0, 0, size, size), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
        byte[] raw = new byte[data.Stride * size];
        Marshal.Copy(data.Scan0, raw, 0, raw.Length);
        b.UnlockBits(data);

        int rowBytes = size * 4;
        int maskStride = ((size + 31) / 32) * 4;
        MemoryStream ms = new MemoryStream();
        BinaryWriter bw = new BinaryWriter(ms);

        bw.Write(40);
        bw.Write(size);
        bw.Write(size * 2);
        bw.Write((short)1);
        bw.Write((short)32);
        bw.Write(0);
        bw.Write(rowBytes * size);
        bw.Write(0);
        bw.Write(0);
        bw.Write(0);
        bw.Write(0);

        for (int y = size - 1; y >= 0; y--) bw.Write(raw, y * data.Stride, rowBytes);

        for (int y = size - 1; y >= 0; y--)
        {
            byte[] row = new byte[maskStride];
            for (int x = 0; x < size; x++)
            {
                if (raw[y * data.Stride + x * 4 + 3] < 128) row[x / 8] |= (byte)(1 << (7 - (x % 8)));
            }
            bw.Write(row);
        }

        bw.Flush();
        byte[] outBytes = ms.ToArray();
        bw.Dispose();
        ms.Dispose();
        return outBytes;
    }

    // 256 px frames are stored PNG-compressed inside the ICO; GDI+ (and Explorer) refuse oversized DIB frames.
    static byte[] PngBytes(Bitmap b)
    {
        MemoryStream ms = new MemoryStream();
        b.Save(ms, ImageFormat.Png);
        byte[] outBytes = ms.ToArray();
        ms.Dispose();
        return outBytes;
    }

    // Renders the master artwork at an arbitrary size, for previews and inspection.
    public static void SavePng(string path, int size)
    {
        Bitmap master = Master();
        Bitmap scaled = Resize(master, size);
        scaled.Save(path, ImageFormat.Png);
        scaled.Dispose();
        master.Dispose();
    }

    public static string Run(string outDir)
    {
        Directory.CreateDirectory(outDir);
        Bitmap master = Master();

        Bitmap preview = Resize(master, 512);
        preview.Save(Path.Combine(outDir, "icon.png"), ImageFormat.Png);
        preview.Dispose();

        int[] sizes = new int[] { 16, 24, 32, 48, 64, 128, 256 };
        List<byte[]> images = new List<byte[]>();
        foreach (int s in sizes)
        {
            Bitmap b = Resize(master, s);
            images.Add(s >= 256 ? PngBytes(b) : DibBytes(b));
            b.Dispose();
        }
        master.Dispose();

        string icoPath = Path.Combine(outDir, "icon.ico");
        FileStream fs = File.Create(icoPath);
        BinaryWriter bw = new BinaryWriter(fs);
        bw.Write((short)0);
        bw.Write((short)1);
        bw.Write((short)sizes.Length);
        int offset = 6 + 16 * sizes.Length;
        for (int i = 0; i < sizes.Length; i++)
        {
            byte dim = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
            bw.Write(dim);
            bw.Write(dim);
            bw.Write((byte)0);
            bw.Write((byte)0);
            bw.Write((short)1);
            bw.Write((short)32);
            bw.Write(images[i].Length);
            bw.Write(offset);
            offset += images[i].Length;
        }
        foreach (byte[] img in images) bw.Write(img);
        bw.Flush();
        bw.Dispose();

        return "icon.png 512x512 / icon.ico " + sizes.Length + " sizes / " + new FileInfo(icoPath).Length + " bytes";
    }
}
