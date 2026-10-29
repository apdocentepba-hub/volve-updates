import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
const root="dist",index=readFileSync(join(root,"index.html"),"utf8");
for (const route of ["ayuda","centros-y-reuniones","proyecto","educacion","colabora","preguntas"]) {
 mkdirSync(join(root,route),{recursive:true});
 writeFileSync(join(root,route,"index.html"),index);
}
console.log("Deep-link entrypoints generated");
