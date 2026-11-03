"""VOLVÉ: Reel/Story originales de prevención, no publicidad de un instalador.
Arte generativo vectorial con Pillow y música instrumental original.
No se fotografían usuarios ni se incorporan recursos de terceros.
"""
from __future__ import annotations
import hashlib, json, subprocess, wave
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import numpy as np

ROOT=Path(__file__).resolve().parent
FRAME_DIR=ROOT/"frames"
W,H=1080,1920
FPS=30
SCENE_DURATION=3.5
CROSSFADE=.30
INK="#11343b"
DEEP="#0c3037"
CREAM="#f4f2e9"
MINT="#a4e6c0"
GOLD="#edc888"
GREY="#566a6b"
FONT="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def ft(size,bold=False):
    return ImageFont.truetype(BOLD if bold else FONT,size)

def canvas(dark=False):
    bg=DEEP if dark else CREAM
    image=Image.new("RGB",(W,H),bg)
    d=ImageDraw.Draw(image)
    if dark:
        d.ellipse((630,-400,1470,470),outline="#2c6263",width=5)
        d.ellipse((720,-310,1350,380),outline="#326e6c",width=3)
        d.ellipse((-350,1180,410,1940),outline="#326e6c",width=4)
    else:
        d.ellipse((695,-340,1450,420),fill="#e8eee2")
        d.ellipse((-450,1190,315,1900),fill="#e6ede5")
        d.ellipse((855,1240,1230,1580),outline="#d6e1d6",width=10)
    return image,d

def header(d,dark=False):
    color=MINT if dark else INK
    d.rounded_rectangle((73,73,375,145),radius=32,outline=color,width=3)
    d.text((110,92),"VOLVÉ",font=ft(37,True),fill=color)
    d.text((810,98),"PREVENCIÓN",font=ft(25,True),fill=color)

def footer(d,dark=False):
    color="#c9e4db" if dark else GREY
    d.line((85,1775,995,1775),fill="#527b79" if dark else "#d1dbd0",width=3)
    d.text((90,1798),"VOLVÉ · PROYECTO INDEPENDIENTE",font=ft(23,True),fill=color)
    d.text((90,1841),"Software gratuito en desarrollo · No reemplaza asistencia",font=ft(20),fill=color)

def lines(d,items,y,color=INK,size=78,leading=1.24):
    f=ft(size,True)
    for t in items:
        d.text((85,int(y)),t,font=f,fill=color,stroke_width=0)
        y+=int(size*leading)
    return int(y)

def badge(d,text,y=254,dark=False):
    color="#315f62" if dark else "#d9eadc"
    ink=MINT if dark else INK
    f=ft(25,True)
    bbox=d.textbbox((0,0),text,font=f)
    w=bbox[2]-bbox[0]+55
    d.rounded_rectangle((85,y,85+w,y+64),radius=27,fill=color)
    d.text((112,y+16),text,font=f,fill=ink)

def shield(d,x=305,y=915,scale=1,dark=False):
    accent=MINT if dark else INK
    soft="#17484e" if dark else "#dfece0"
    rr=lambda n:int(n*scale)
    d.ellipse((x-rr(210),y-rr(205),x+rr(210),y+rr(235)),fill=soft)
    points=[
        (x,y-rr(144)),(x+rr(115),y-rr(96)),(x+rr(110),y+rr(35)),
        (x+rr(60),y+rr(122)),(x,y+rr(161)),(x-rr(60),y+rr(122)),
        (x-rr(110),y+rr(35)),(x-rr(115),y-rr(96))]
    d.polygon(points,outline=accent,width=13)
    d.line([(x-rr(47),y+rr(11)),(x-rr(12),y+rr(48)),(x+rr(65),y-rr(45))],fill=accent,width=16,joint="curve")

def panel(d,x,y,w,h,dark=False):
    d.rounded_rectangle((x,y,x+w,y+h),radius=48,fill="#194b51" if dark else "#ffffff",
                        outline="#3b7870" if dark else "#c9d9cc",width=4)

def intro():
    im,d=canvas(False);header(d)
    badge(d,"APUESTAS ONLINE · AYUDA REAL")
    lines(d,["¿Las apuestas","están ocupando","demasiado","espacio?"],390,INK,77,1.18)
    panel(d,92,955,894,555)
    shield(d,298,1230,.68,False)
    d.text((500,1098),"No tenés que",font=ft(48,True),fill=INK)
    d.text((500,1168),"enfrentarlo",font=ft(48,True),fill=INK)
    d.text((500,1238),"a solas.",font=ft(48,True),fill=INK)
    d.text((142,1440),"Hay recursos gratuitos disponibles hoy.",font=ft(31,True),fill=INK)
    d.text((91,1627),"Guardá este video por si lo necesitás.",font=ft(30),fill=GREY)
    footer(d)
    return im

def phone_scene():
    im,d=canvas(True);header(d,True)
    badge(d,"PROVINCIA DE BUENOS AIRES",dark=True)
    lines(d,["Orientación","gratuita"],415,CREAM,87,1.18)
    panel(d,80,740,920,585,True)
    d.text((125,845),"LLAMÁ AL",font=ft(47,True),fill=MINT)
    d.text((116,950),"0800-444-",font=ft(93,True),fill=CREAM)
    d.text((116,1060),"4000",font=ft(127,True),fill=CREAM)
    d.text((124,1210),"Programa provincial de asistencia",font=ft(25),fill="#d4ebe2")
    d.text((100,1430),"Teléfono oficial de Lotería PBA.",font=ft(36,True),fill=CREAM)
    d.text((100,1495),"También orienta a las familias.",font=ft(33),fill="#c4dfd7")
    footer(d,True)
    return im

def centers():
    im,d=canvas(False);header(d)
    badge(d,"RECURSOS PRESENCIALES Y VIRTUALES")
    lines(d,["También hay","centros y","reuniones"],407,INK,82,1.2)
    panel(d,87,800,906,652)
    d.text((139,870),"45 recursos",font=ft(81,True),fill=INK)
    d.text((141,974),"en Provincia de Buenos Aires",font=ft(28,True),fill=GREY)
    for i,(main,sub) in enumerate([
        ("Centros públicos","orientación y asistencia"),
        ("Reuniones de apoyo","presenciales y virtuales"),
        ("Recursos para familias","consultá antes de asistir")]):
        y=1065+i*117
        d.ellipse((141,y,181,y+40),fill=MINT)
        d.text((157,y+1),"✓",font=ft(20,True),fill=INK)
        d.text((205,y-8),main,font=ft(31,True),fill=INK)
        d.text((205,y+39),sub,font=ft(25),fill=GREY)
    d.text((107,1585),"Confirmá días y horarios con cada entidad.",font=ft(27,True),fill=INK)
    footer(d)
    return im

def honesty():
    im,d=canvas(True);header(d,True)
    badge(d,"TRANSPARENCIA SOBRE VOLVÉ",dark=True)
    lines(d,["VOLVÉ está","en desarrollo"],400,CREAM,81,1.23)
    panel(d,85,765,910,580,True)
    d.text((126,862),"PROTECCIÓN",font=ft(54,True),fill=MINT)
    d.text((126,938),"VOLUNTARIA",font=ft(54,True),fill=MINT)
    d.text((127,1054),"Software gratuito para sumar",font=ft(32),fill=CREAM)
    d.text((127,1113),"barreras frente a sitios de apuestas.",font=ft(30),fill=CREAM)
    d.line((125,1177,937,1177),fill="#397076",width=3)
    d.text((126,1222),"Sin descarga pública estable todavía.",font=ft(27,True),fill=GOLD)
    d.text((97,1450),"La ayuda profesional y comunitaria",font=ft(34),fill=CREAM)
    d.text((97,1517),"no depende de este software.",font=ft(34,True),fill=CREAM)
    footer(d,True)
    return im

def final():
    im,d=canvas(False);header(d)
    badge(d,"ENLACE DIRECTO EN LA HISTORIA")
    lines(d,["Encontrá ayuda","sin registrarte"],405,INK,76,1.25)
    panel(d,91,815,900,632)
    d.text((134,890),"Una sola página con:",font=ft(41,True),fill=INK)
    for i,t in enumerate(["Línea gratuita PBA","Buscador de 45 recursos","Prevención y proyecto"]):
        y=987+i*119
        d.rounded_rectangle((131,y-9,931,y+76),radius=22,fill="#e6eee4")
        d.text((160,y+9),"●",font=ft(27),fill="#2e7465")
        d.text((211,y+6),t,font=ft(33,True),fill=INK)
    d.text((124,1536),"volve-web.onrender.com/instagram",font=ft(29,True),fill=INK)
    d.text((124,1602),"Tocá el enlace de la historia",font=ft(31),fill=GREY)
    footer(d)
    return im

def story():
    im,d=canvas(True);header(d,True)
    badge(d,"AYUDA GRATUITA · PROVINCIA DE BUENOS AIRES",dark=True)
    lines(d,["Si necesitás","orientación,"],385,CREAM,91,1.23)
    lines(d,["hay ayuda."],650,MINT,108,1.2)
    panel(d,88,855,904,590,True)
    d.text((134,905),"Línea oficial PBA",font=ft(40,True),fill=MINT)
    d.text((122,1003),"0800-444-",font=ft(90,True),fill=CREAM)
    d.text((122,1123),"4000",font=ft(120,True),fill=CREAM)
    d.text((133,1320),"Centros y reuniones de ayuda",font=ft(28),fill=CREAM)
    d.text((122,1535),"Abrí el enlace de esta historia",font=ft(36,True),fill=MINT)
    d.text((122,1597),"volve-web.onrender.com/instagram",font=ft(26),fill=CREAM)
    footer(d,True)
    return im

def music(total):
    rate=32000
    t=np.arange(round(rate*(total+.1)),dtype=np.float64)/rate
    notes=[146.83,174.61,220.,261.63,196.,164.81]
    x=np.zeros_like(t)
    for i,f in enumerate(notes):
        x+=0.060*np.sin(2*np.pi*f*t+0.15*i)
        x+=0.022*np.sin(2*np.pi*(f/2)*t+.5*i)
    env=np.clip(t/0.7,0,1)*np.clip((total-t)/0.95,0,1)
    pulse=.65+.35*np.sin(2*np.pi*(1/4.0)*t)**2
    signal=np.tanh(x*1.8)*env*pulse
    pcm=np.stack([signal,signal*.97],axis=-1)
    f=ROOT/"original_audio.wav"
    with wave.open(str(f),"wb") as w:
        w.setframerate(rate);w.setnchannels(2);w.setsampwidth(2)
        w.writeframes(np.round(pcm*32767).astype(np.int16).tobytes())
    return f

def render():
    ROOT.mkdir(parents=True,exist_ok=True)
    FRAME_DIR.mkdir(parents=True,exist_ok=True)
    scenes=[intro(),phone_scene(),centers(),honesty(),final()]
    for i,frame in enumerate(scenes):
        path=FRAME_DIR/f"scene_{i:02}.jpg"
        frame.save(path,quality=92,subsampling=0)
        assert path.stat().st_size>50000
        print("FRAME_OK",path.name,frame.size,flush=True)
    last=story()
    last.save(ROOT/"volve_ayuda_story.jpg",quality=93,subsampling=0)
    grid=Image.new("RGB",(900,1155),CREAM)
    for i,im in enumerate(scenes+[last]):
        x=(i%3)*300;y=(i//3)*576
        grid.paste(im.resize((289,514),Image.Resampling.LANCZOS),(x+5,y+6))
    grid.save(ROOT/"contact_sheet.jpg",quality=90)

    duration=round(len(scenes)*SCENE_DURATION-(len(scenes)-1)*CROSSFADE,2)
    audio=music(duration)
    args=[]
    fc=[]
    for i in range(len(scenes)):
        args+=["-loop","1","-framerate",str(FPS),"-t",str(SCENE_DURATION),"-i",str(FRAME_DIR/f"scene_{i:02}.jpg")]
        fc.append(f"[{i}:v]scale={W}:{H},format=yuv420p,setsar=1,trim=duration={SCENE_DURATION},setpts=PTS-STARTPTS[v{i}]")
    prev="v0"
    for i in range(1,len(scenes)):
        offset=round(i*(SCENE_DURATION-CROSSFADE),2)
        dest=f"x{i}"
        fc.append(f"[{prev}][v{i}]xfade=transition=fade:duration={CROSSFADE}:offset={offset}[{dest}]")
        prev=dest
    video=ROOT/"volve_ayuda_reel.mp4"
    cmd=["ffmpeg","-y","-hide_banner","-loglevel","error",*args,"-i",str(audio),
         "-filter_complex",";".join(fc),"-map",f"[{prev}]","-map",f"{len(scenes)}:a",
         "-c:v","libx264","-preset","veryfast","-crf","22","-pix_fmt","yuv420p",
         "-r",str(FPS),"-c:a","aac","-b:a","128k","-ar","44100",
         "-movflags","+faststart","-t",str(duration),str(video)]
    subprocess.run(cmd,check=True,timeout=180)
    info=json.loads(subprocess.check_output(["ffprobe","-v","error","-show_format","-show_streams","-of","json",str(video)],text=True))
    av={s["codec_type"]:s for s in info["streams"]}
    assert av["video"]["codec_name"]=="h264" and av["audio"]["codec_name"]=="aac"
    assert int(av["video"]["width"])==1080 and int(av["video"]["height"])==1920
    assert 15<=float(info["format"]["duration"])<=17
    assert 500000<=video.stat().st_size<=45000000
    output={
        "brand":"VOLVÉ · Prevención", "instagram":"@volveprevencion",
        "landing":"https://volve-web.onrender.com/instagram",
        "official_source":"https://loteria.gba.gob.ar/juego-compulsivo",
        "official_help_phone":"0800-444-4000",
        "resource_count":45,"resource_scope":"45 recursos del directorio VOLVÉ PBA; verificar horarios",
        "software_status":"Windows en desarrollo; sin descarga pública estable",
        "video":{"name":video.name,"bytes":video.stat().st_size,"sha256":hashlib.sha256(video.read_bytes()).hexdigest(),"duration":float(info["format"]["duration"]),"width":W,"height":H,"fps":FPS,"audio":"música sintetizada original"},
        "story":{"name":"volve_ayuda_story.jpg","bytes":(ROOT/"volve_ayuda_story.jpg").stat().st_size,"sha256":hashlib.sha256((ROOT/"volve_ayuda_story.jpg").read_bytes()).hexdigest()},
        "privacy":"No faces, personal data, clients, accounts, cookies, or health claims.",
    }
    (ROOT/"manifest.json").write_text(json.dumps(output,ensure_ascii=False,indent=2)+"\n",encoding="utf8")
    print("VIDEO_AND_STORY_VERIFIED",json.dumps(output,ensure_ascii=False),flush=True)

if __name__=="__main__":
    render()
