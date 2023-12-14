import { PeprModule } from "pepr";
import cfg from "./package.json";

import { SecurityPolicy } from "./capabilities/security";

new PeprModule(cfg, [SecurityPolicy]);
