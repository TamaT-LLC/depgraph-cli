"use server";

function handler(): Response {
  return new Response("shared");
}

export { handler as GET, handler as POST };
