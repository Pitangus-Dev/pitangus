// ruleid: appsec.js.react-dangerously-set-inner-html
export const V = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;

export function Safe({ text }) {
  // ok: appsec.js.react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: "<b>fixed</b>" }} />;
}
