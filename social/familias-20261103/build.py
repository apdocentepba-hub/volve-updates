"""VOLVÉ · Carrusel Instagram para familiares y amigos (4 placas originales).
No se recolectan datos, no se publica automáticamente ni se contactan terceros.
Fuentes: https://loteria.gba.gob.ar/juego-compulsivo
         https://jug-anon.org.ar/pages/grupos-autoayuda.html
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parent
W,H=1080,1350
DARK="#0b3038"
DEEP="#123d43"
TEAL="#176b63"
MINT="#b9e8cd"
OFF="#f4f3eb"
PALE="#e6eee7"
GOLD="#e7bb75"
WHITE="#ffffff"
MUTED="#a9cccb"
INK="#12383e"
FONT="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def font(px,bold=False):
    return ImageFont.truetype(BOLD if bold else FONT,px)

def text(d, words, xy, px=40, color=INK, bold=False, maxw=None):
    f=font(px,bold)
    if maxw:
        box=d.textbbox((0,0),words,font=f)
        if box[2]-box[0]>maxw:
            raise ValueError(f"Text too wide ({box[2]-box[0]}>{maxw}): {words}")
    d.text(xy,words,font=f,fill=color)
    return xy[1]+px

def base(num,dark=False):
    im=Image.new("RGB",(W,H),DARK if dark else OFF)
    d=ImageDraw.Draw(im)
    if dark:
        d.ellipse((745,-190,1370,440),outline="#2e6268",width=5)
        d.ellipse((830,-90,1310,310),outline="#255b62",width=3)
        d.ellipse((-230,960,245,1530),outline="#20555b",width=5)
    else:
        d.ellipse((748,-170,1400,450),fill=PALE)
        d.ellipse((-255,1050,280,1600),fill=PALE)
    c=MINT if dark else TEAL
    d.rounded_rectangle((72,60,314,128),radius=28,outline=c,width=3)
    text(d,"VOLVÉ",(99,74),36,c,True,195)
    text(d,"PREVENCIÓN",(793,84),23,c,True,236)
    d.line((74,1265,1006,1265),fill="#3c7375" if dark else "#cad5cc",width=2)
    text(d,"RECURSOS GRATUITOS · SIN REGISTRO",(82,1283),18,MUTED if dark else "#607577",True,700)
    text(d,f"{num} / 4",(936,1281),22,c,True,72)
    return im,d

def multiline(d,lines,at_y,px,color,bold=True,leading=None):
    yy=at_y
    for line in lines:
        text(d,line,(82,yy),px,color,bold,925)
        yy+=leading or int(px*1.26)
    return yy

def tag(d,value,y,dark=False):
    f=font(26,True)
    w=d.textbbox((0,0),value,font=f)[2]
    d.rounded_rectangle((78,y,128+w,y+62),radius=24,fill=DEEP if dark else "#e0ebe2")
    text(d,value,(104,y+15),26,MINT if dark else TEAL,True,830)

def roundcard(d,xy,fill,stroke=None,rad=30):
    d.rounded_rectangle(xy,radius=rad,fill=fill,outline=stroke,width=3 if stroke else 1)

def item(d,n,title,sub,y):
    roundcard(d,(78,y,1002,y+154),WHITE,"#d6e0d9",28)
    d.ellipse((107,y+44,167,y+104),fill=TEAL)
    text(d,str(n),(126,y+57),30,WHITE,True,35)
    text(d,title,(190,y+28),35,INK,True,790)
    text(d,sub,(190,y+83),25,"#54696a",False,770)

def slide1():
    im,d=base(1,True)
    tag(d,"PARA FAMILIARES Y AMIGOS",226,True)
    multiline(d,["¿Alguien que","querés está","apostando y","te preocupa?"],326,75,WHITE,True,104)
    roundcard(d,(75,804,1004,1085),DEEP,"#38757a")
    text(d,"Vos también merecés apoyo.",(113,862),44,MINT,True,820)
    text(d,"Hay maneras de acompañar",(114,936),34,WHITE,False,840)
    text(d,"sin dejar de cuidarte.",(114,985),34,WHITE,False,840)
    text(d,"Deslizá para ver opciones de ayuda.",(83,1160),27,MUTED,False,900)
    return im

def slide2():
    im,d=base(2)
    tag(d,"01 · CONVERSAR",226)
    multiline(d,["Empezá por","una charla","respetuosa."],342,76,INK,True,103)
    item(d,1,"Elegí un momento tranquilo","Sin discusiones ni reproches.",720)
    item(d,2,"Hablá de lo que observás","Y de cómo te está afectando.",893)
    roundcard(d,(77,1090,1005,1205),"#dcece0")
    text(d,"No necesitás resolver todo de una vez.",(104,1134),29,INK,True,870)
    return im

def slide3():
    im,d=base(3)
    tag(d,"02 · CUIDARTE",226)
    multiline(d,["Acompañar","también incluye","poner límites."],342,74,INK,True,105)
    item(d,1,"Protegé tus recursos","Cuidá tu dinero y tus acuerdos.",720)
    item(d,2,"Pedí apoyo para vos","Familiares y amigos también pueden ir.",893)
    roundcard(d,(77,1090,1005,1205),"#dcece0")
    text(d,"Buscar orientación es una posibilidad.",(104,1134),30,INK,True,877)
    return im

def slide4():
    im,d=base(4,True)
    tag(d,"03 · ENCONTRAR AYUDA",215,True)
    multiline(d,["Hay orientación","gratuita para","personas y familias."],306,61,WHITE,True,88)
    roundcard(d,(75,625,1005,903),DEEP,"#34777b",28)
    text(d,"PROGRAMA OFICIAL PBA",(114,664),28,MINT,True,800)
    text(d,"0800-444-4000",(103,737),60,WHITE,True,865)
    text(d,"Prevención y asistencia al juego compulsivo",(115,834),23,MUTED,False,842)
    roundcard(d,(75,926,1005,1112),"#194b50","#34777b",28)
    text(d,"JUG-ANON: grupos para familiares",(107,960),31,MINT,True,876)
    text(d,"y amigos. Confirmá lugares y horarios",(107,1012),24,WHITE,False,876)
    text(d,"en su sitio oficial.",(107,1051),24,WHITE,False,860)
    text(d,"Más recursos: enlace en bio de @volveprevencion",(82,1175),22,MUTED,True,924)
    return im

def main():
    ROOT.mkdir(parents=True,exist_ok=True)
    images=[slide1(),slide2(),slide3(),slide4()]
    out=[]
    for i,im in enumerate(images,1):
        assert im.size==(W,H)
        p=ROOT/f"volve_familias_{i:02d}.png"
        im.save(p,optimize=True)
        with Image.open(p) as x:
            assert x.size==(W,H)
            x.verify()
        sha=hashlib.sha256(p.read_bytes()).hexdigest()
        assert 25000<p.stat().st_size<1800000
        out.append({"name":p.name,"bytes":p.stat().st_size,"sha256":sha})
        print("CARD_OK",i,p.stat().st_size,flush=True)
    board=Image.new("RGB",(844,1090),OFF)
    for i,im in enumerate(images):
        thumb=im.resize((400,500),Image.Resampling.LANCZOS)
        board.paste(thumb,(14+(i%2)*414,15+(i//2)*538))
    board.save(ROOT/"contact_sheet.jpg",quality=92)
    manifest={
        "brand":"VOLVÉ Prevención","instagram":"@volveprevencion",
        "platform":"Instagram carousel", "cards":out,
        "sources":["https://loteria.gba.gob.ar/juego-compulsivo",
                   "https://jug-anon.org.ar/pages/grupos-autoayuda.html"],
        "disclaimers":"Educación y recursos para familias; no reemplaza asistencia profesional ni garantiza resultados.",
        "facts":["Línea oficial PBA 0800-444-4000", "JUG-ANON asiste a familiares y amigos"],
        "privacy":"Sin datos personales, casos reales, marcas ajenas, cookies ni formularios.",
        "publishing":"No publicar desde CI; entregar PNG en rama marketing"
    }
    (ROOT/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf8")
    print("VOLVE_FAMILY_CAROUSEL_READY",json.dumps({"cards":len(out),"hashes":[o["sha256"] for o in out]},ensure_ascii=False),flush=True)

if __name__=="__main__":
    main()
