import type { Value } from "@/lib/value";
import { value } from "@/lib/value";
import { shared } from "@fixture/shared";
import { shared as sharedAlias } from "@shared/index";
import lodash from "lodash";
import "./missing";
export { item } from "multi/item";

const commonJs = require("@/lib/value");
const lazy = import("@/lib/value");
const segment = "value";
const unknown = import(`@/lib/${segment}`);

export default function Product(): string {
  return String(value + shared.length + sharedAlias.length + lodash.size(commonJs) + Number(lazy) + Number(unknown));
}

export type ProductValue = Value;
