import { redirect } from "next/navigation";

/** Root redirects to the Settings page. */
export default function Root() {
  redirect("/settings");
}
