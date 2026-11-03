"""Genera un kit A4 original de VOLVÉ para imprimir y compartir.
Sin imágenes ni textos copiados de terceros. Fuentes oficiales al pie.
Uso: python site/scripts/build-school-kit.py
"""
from pathlib import Path
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor as HC
from reportlab.lib.utils import ImageReader, simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import qrcode

PDF=Path(__file__).resolve().parents[1]/"public"/"kit-escolar-volve.pdf"
PDF.parent.mkdir(exist_ok=True,parents=True)
W,H=A4
DARK=HC("#0c343b"); DEEP=HC("#15494f"); GREEN=HC("#176f64")
MINT=HC("#b9e8ce"); OFF=HC("#f5f3eb"); INK=HC("#17373c")
GREY=HC("#587072"); WHITE=HC("#ffffff"); GOLD=HC("#f0c98a")
BORDER=HC("#d0ddd4"); LIGHT=HC("#e8eee8")
pdfmetrics.registerFont(TTFont("Regular","/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("Bold","/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"))
S="https://volve-web.onrender.com/escuelas"
UNICEF="https://www.unicef.org/argentina/informes/guia-apuestas-online"
TEACHER="https://www.unicef.org/argentina/informes/guia-docentes-educacion-financiera"
LOT="https://loteria.gba.gob.ar/juego-compulsivo"
JUG="https://jug-anon.org.ar/pages/grupos-autoayuda.html"

def rect(c,x,t,w,h,color,r=12,border=None):
 c.setFillColor(color);c.setStrokeColor(border or color);c.setLineWidth(.75)
 c.roundRect(x,H-t-h,w,h,r,fill=1,stroke=int(border is not None))

def text(c,x,t,s,n=10,color=INK,bold=False):
 c.setFillColor(color);c.setFont("Bold" if bold else "Regular",n)
 c.drawString(x,H-t-n,s)

def paragraph(c,x,t,s,w,n=9,leading=14,color=INK,bold=False):
 y=t
 for section in s.split("\n"):
  for line in simpleSplit(section,"Bold" if bold else "Regular",n,w):
   text(c,x,y,line,n,color,bold)
   y+=leading
 return y

def foot(c,number):
 c.setStrokeColor(BORDER);c.setLineWidth(.7);c.line(42,28,W-42,28)
 text(c,43,817,"VOLVÉ · Material educativo gratuito · Noviembre 2026",7,GREY)
 text(c,528,817,f"{number} / 3",7,GREY,True)

def panel(c,title,subtitle,number):
 c.setFillColor(DARK);c.rect(0,H-130,W,130,fill=1,stroke=0)
 text(c,42,29,"VOLVÉ · PREVENCIÓN",11,MINT,True)
 text(c,42,66,title,24,WHITE,True)
 text(c,43,106,subtitle,9,MINT)
 foot(c,number)

def first(c):
 c.setFillColor(WHITE);c.rect(0,0,W,H,fill=1,stroke=0)
 c.setFillColor(DARK);c.rect(0,H-352,W,352,fill=1,stroke=0)
 c.setFillColor(DEEP);c.circle(550,H+40,150,fill=1,stroke=0)
 text(c,42,39,"VOLVÉ · PREVENCIÓN",11,MINT,True)
 text(c,42,76,"PARA ESCUELAS Y FAMILIAS",10,GOLD,True)
 text(c,42,125,"APUESTAS",41,WHITE,True)
 text(c,42,176,"ONLINE",41,MINT,True)
 text(c,42,245,"HABLAR A TIEMPO TAMBIÉN ES PREVENIR",14.5,GOLD,True)
 paragraph(c,42,289,"Información gratuita para abrir conversaciones, reconocer señales de preocupación y encontrar orientación sin juzgar.",465,10.5,16,WHITE)
 text(c,42,373,"Tres formas de empezar",16.5,INK,True)
 info=[
   ("01","Hablá","Preguntá qué ven online sin retos ni sermones."),
   ("02","Escuchá","Evitá suposiciones; conocé lo que les preocupa."),
   ("03","Acompañá","Buscá un adulto o recurso confiable."),
 ]
 for i,(num,head,body) in enumerate(info):
  x=42+i*174
  rect(c,x,410,163,128,OFF,13,BORDER)
  text(c,x+14,424,num,11,GREEN,True)
  text(c,x+14,458,head,15,INK,True)
  paragraph(c,x+14,488,body,138,9.4,13,GREY)
 rect(c,42,558,W-84,148,DARK,18)
 text(c,60,575,"ORIENTACIÓN GRATUITA EN PBA",10,MINT,True)
 text(c,59,606,"0800-444-4000",26,WHITE,True)
 paragraph(c,60,644,"Programa provincial de prevención y asistencia al juego compulsivo para personas y familias.",317,9.2,14,WHITE)
 qr=qrcode.QRCode(box_size=8,border=1,error_correction=qrcode.constants.ERROR_CORRECT_M)
 qr.add_data(S);qr.make(fit=True)
 bi=BytesIO();qr.make_image(fill_color="#0c343b",back_color="white").convert("RGB").save(bi,format="PNG");bi.seek(0)
 rect(c,414,572,113,113,WHITE,10)
 c.drawImage(ImageReader(bi),422,H-678,97,97)
 c.linkURL(S,(414,H-685,527,H-572),relative=0,thickness=0)
 text(c,424,687,"Escaneá y compartí",7.6,MINT,True)
 text(c,42,727,"En peligro inmediato: 911. Orientación para menores: 102. Consumos: 141.",8.7,INK,True)
 paragraph(c,42,750,"No reemplaza la atención profesional. VOLVÉ es independiente y no representa ni tiene convenio con los organismos citados.",507,8.5,12,GREY)
 text(c,42,782,"Fuentes: UNICEF Argentina · Lotería de la Provincia de Buenos Aires.",7.8,GREY)
 c.linkURL(UNICEF,(42,H-800,228,H-780),relative=0,thickness=0)
 c.linkURL(LOT,(235,H-800,525,H-780),relative=0,thickness=0)
 foot(c,1);c.showPage()

def second(c):
 c.setFillColor(WHITE);c.rect(0,0,W,H,fill=1,stroke=0)
 panel(c,"Una actividad de 15 minutos","Para secundaria · Adaptar al grupo y al contexto institucional",2)
 rect(c,42,154,511,80,OFF,14,BORDER)
 text(c,57,165,"ANTES DE EMPEZAR",10,GREEN,True)
 paragraph(c,57,187,"No pidas que estudiantes cuenten experiencias personales de apuestas, dinero perdido o problemas familiares delante del curso. Usá ejemplos ficticios.",473,9.2,14,INK)
 text(c,42,252,"Secuencia para el aula",16,INK,True)
 steps=[
  ("0-3 min","Abrir la conversación","¿Qué diferencia hay entre un videojuego y apostar dinero para ganar más?"),
  ("3-7 min","Leer un caso ficticio","Una influencer promete créditos gratis para apostar en fútbol. ¿Qué señales nos harían desconfiar?"),
  ("7-12 min","Analizar sin juzgar","En grupos: presión social, ganancia rápida, riesgo económico y dónde pedir orientación."),
  ("12-15 min","Cerrar con recursos","Apostar dinero es una actividad para mayores de 18 años. Compartí el 0800-444-4000."),
 ]
 for i,(when,title,body) in enumerate(steps):
  top=292+109*i
  rect(c,42,top,511,96,WHITE,14,BORDER)
  rect(c,56,top+14,89,28,LIGHT,11)
  text(c,65,top+21,when,9.3,GREEN,True)
  text(c,157,top+15,title,12.1,INK,True)
  paragraph(c,157,top+41,body,371,9.3,13,GREY)
 rect(c,42,742,511,58,DARK,12)
 text(c,58,751,"Para ampliar la actividad",10,MINT,True)
 paragraph(c,58,771,"UNICEF: guía para docentes sobre educación financiera y apuestas online.",472,8.8,12,WHITE)
 c.linkURL(TEACHER,(42,H-800,553,H-742),relative=0,thickness=0)
 foot(c,2);c.showPage()

def third(c):
 c.setFillColor(WHITE);c.rect(0,0,W,H,fill=1,stroke=0)
 panel(c,"Orientación para familias","Señales, diálogo y recursos · Sin juicios ni diagnósticos",3)
 text(c,42,155,"Cambios a los que prestar atención",15.2,INK,True)
 paragraph(c,42,181,"Una señal aislada no demuestra un problema. Importan los cambios persistentes y el contexto.",510,9.3,14,GREY)
 flags=[
  ("Relaciones","Aislamiento, discusiones o dejar actividades habituales."),
  ("Dinero","Gastos sin explicación o deseo de recuperar pérdidas."),
  ("Bienestar","Angustia, irritabilidad o cambios de sueño."),
  ("Uso digital","Preocupación frecuente por resultados y apuestas."),
 ]
 for i,(heading,body) in enumerate(flags):
  col,row=i%2,i//2;x=42+263*col;t=218+114*row
  rect(c,x,t,249,100,OFF,13,BORDER)
  text(c,x+15,t+14,heading,11.2,GREEN,True)
  paragraph(c,x+15,t+38,body,219,9.2,13,INK)
 text(c,42,465,"Cómo conversar sin exponer ni avergonzar",15,INK,True)
 prompts=[
  ("1","Elegí un momento tranquilo","Quisiera entender qué te aparece en redes sobre apuestas."),
  ("2","Escuchá y preguntá","¿Qué te atrae de eso? ¿Hay algo que te preocupe?"),
  ("3","Acordá próximos pasos","Busquen juntos ayuda y recursos especializados."),
 ]
 for i,(number,title,body) in enumerate(prompts):
  top=506+i*57
  c.setFillColor(GREEN);c.circle(57,H-top-15,15,fill=1,stroke=0)
  text(c,53,top+6,number,10,WHITE,True)
  text(c,83,top,title,10.7,INK,True)
  paragraph(c,83,top+21,body,461,8.9,12,GREY)
 rect(c,42,692,511,93,DARK,15)
 text(c,59,704,"¿DÓNDE CONSULTAR?",10,MINT,True)
 text(c,59,727,"0800-444-4000",19.6,WHITE,True)
 text(c,335,733,"PBA · GRATUITO",9.1,MINT,True)
 paragraph(c,59,759,"JUG-ANON: grupos para familiares (confirmar horarios). En peligro inmediato, 911.",478,8.4,12,WHITE)
 c.linkURL(LOT,(42,H-759,330,H-690),relative=0,thickness=0)
 c.linkURL(JUG,(42,H-785,553,H-755),relative=0,thickness=0)
 foot(c,3);c.showPage()

cv=canvas.Canvas(str(PDF),pagesize=A4,pageCompression=1)
cv.setTitle("VOLVÉ · Kit gratuito para escuelas y familias")
cv.setAuthor("VOLVÉ Prevención · Proyecto independiente")
cv.setSubject("Prevención de apuestas online, material original para imprimir · noviembre 2026")
first(cv);second(cv);third(cv);cv.save()
print("VOLVE_KIT_PDF_OK",PDF,PDF.stat().st_size)
