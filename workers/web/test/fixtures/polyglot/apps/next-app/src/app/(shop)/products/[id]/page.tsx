"use cache";

import type { Value } from "@/lib/value";
import { value } from "@/lib/value";
import { shared } from "@fixture/shared";
import { shared as sharedAlias } from "@shared/index";
import ClientPanel from "../../../ClientPanel";
import dynamic from "next/dynamic";
import lodash from "lodash";
import "./missing";
export { item } from "multi/item";

const commonJs = require("@/lib/value");
const lazy = import("@/lib/value");
const segment = "value";
const unknown = import(`@/lib/${segment}`);
const LazyPanel = dynamic(() => import("../../../LazyPanel"));
const SelectedPanel = dynamic(() => import("../../../LazyPanel").then((module) => module.default));
const UnknownPanel = dynamic(() => import(`../../../${segment}`));

export const runtime = "edge";

export default function Product(): unknown {
  return <><ClientPanel /><LazyPanel />{String(value + shared.length + sharedAlias.length + lodash.size(commonJs) + Number(lazy) + Number(unknown) + Number(SelectedPanel) + Number(UnknownPanel))}</>;
}

export type ProductValue = Value;
