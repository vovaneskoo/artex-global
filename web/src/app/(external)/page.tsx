import { redirect } from "next/navigation";

export default function Home() {
  redirect("/operator");
  return <>Coming Soon</>;
}
