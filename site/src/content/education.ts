export type EduNote = {
  slug: string;
  tag: string;
  title: string;
  summary: string;
  body?: { heading: string; text: string }[];
};

/** Base de contenido educativo. Agregá o editá notas acá. */
export const notes: EduNote[] = [
  {
    slug: "por-que-cuesta-frenar",
    tag: "Entender",
    title: "Por qué cuesta tanto frenar",
    summary:
      "Las apuestas online combinan premios impredecibles, disponibilidad 24/7 y dinero que se siente “virtual”. No es falta de voluntad: el diseño empuja a seguir.",
    body: [
      { heading: "Refuerzo intermitente", text: "Ganar de vez en cuando, sin saber cuándo, es uno de los patrones que más sostienen una conducta. Cada intento parece “el que puede salir”." },
      { heading: "Cero fricción", text: "El celular está siempre a mano. Depositar lleva segundos y no hay un momento natural para cortar, como cuando cierra un lugar físico." },
      { heading: "Casi ganar", text: "Quedar cerca de un premio se vive como señal de que falta poco, aunque cada jugada sea independiente de la anterior." },
      { heading: "Qué podés hacer", text: "Sumar fricción ayuda: tiempo entre el impulso y la acción. Ahí entran las barreras voluntarias, los límites y hablar con alguien." },
    ],
  },
  {
    slug: "senales-para-mirar",
    tag: "Prevenir",
    title: "Señales para mirar con cariño",
    summary:
      "No para diagnosticar a nadie, sino para darnos cuenta a tiempo: cuando apostar empieza a ocupar más lugar del que queremos.",
    body: [
      { heading: "Perseguir pérdidas", text: "Volver a apostar para “recuperar” lo perdido suele agrandar el problema en vez de resolverlo." },
      { heading: "Ocultar o minimizar", text: "Esconder movimientos, borrar historiales o cambiar de tema cuando sale el asunto." },
      { heading: "Afecta lo importante", text: "Plata de gastos fijos, sueño, estudio, trabajo o vínculos empiezan a resentirse." },
      { heading: "Si te reconocés", text: "No estás solo ni sola. Pedir ayuda es un paso valiente, y hay líneas gratuitas y confidenciales para hablar." },
    ],
  },
  {
    slug: "adolescentes",
    tag: "Familias",
    title: "Adolescentes y apuestas: hablar sin retar",
    summary:
      "La publicidad y los grupos de pares normalizan apostar. Una conversación abierta suele funcionar mejor que el castigo.",
  },
  {
    slug: "barreras",
    tag: "Herramientas",
    title: "Barreras digitales: qué son y qué no",
    summary:
      "Un bloqueo voluntario agrega tiempo y distancia frente al impulso. No es infalible y no reemplaza el acompañamiento: es una ayuda más.",
  },
  {
    slug: "plata",
    tag: "Cuidarse",
    title: "Ordenar la plata para proteger el día a día",
    summary:
      "Delegar temporalmente tarjetas, poner límites en billeteras virtuales y separar gastos fijos reduce el margen para apostar en caliente.",
  },
  {
    slug: "recaidas",
    tag: "Recuperación",
    title: "Si volviste a apostar, no empezás de cero",
    summary:
      "Las recaídas forman parte de muchos procesos. Lo importante es volver a pedir apoyo y revisar qué barreras sumar.",
  },
];

export const upcoming = [
  "Guía para familias: cómo acompañar sin controlar",
  "Flyer imprimible para escuelas técnicas y centros comunitarios",
  "Cómo configurar límites en billeteras virtuales",
];