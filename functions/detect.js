// functions/detect.js
export async function onRequest(context) {
  const url = new URL(context.request.url);
  const domain = (url.searchParams.get('domain') || (await context.request.json().then(r=>r.domain).catch(()=>null)) || '').trim().toLowerCase();
  if (!domain) return new Response(JSON.stringify({ error: 'Missing domain' }), { status: 400 });

  async function doh(name, type='A') {
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`;
    const r = await fetch(dohUrl, { headers: { Accept: 'application/dns-json' }});
    if (!r.ok) return null;
    return await r.json();
  }

  const aJson = await doh(domain, 'A');
  const ipv4 = (aJson && aJson.Answer) ? aJson.Answer.filter(a=>a.type===1).map(a=>a.data) : [];

  const nsJson = await doh(domain, 'NS');
  const nameservers = (nsJson && nsJson.Answer) ? nsJson.Answer.map(a=>a.data.replace(/\.$/,'').toLowerCase()) : [];

  let headers = {};
  async function tryFetch(proto){
    try {
      const r = await fetch(`${proto}://${domain}`, { method: 'HEAD', redirect: 'manual', cf: { cacheTtl: 0 } });
      const h = {};
      ['server','cf-ray','cf-cache-status','via','x-powered-by'].forEach(k=>{
        const v = r.headers.get(k);
        if (v) h[k] = v;
      });
      return { ok:true, status: r.status, headers: h };
    } catch(e){ return { ok:false, error: String(e) }; }
  }
  let httpInfo = await tryFetch('https');
  if (!httpInfo.ok) httpInfo = await tryFetch('http');

  const cfV4txt = await (await fetch('https://www.cloudflare.com/ips-v4')).text();
  const cfV6txt = await (await fetch('https://www.cloudflare.com/ips-v6')).text();
  const cfRanges = cfV4txt.split(/\r?\n/).concat(cfV6txt.split(/\r?\n/)).filter(Boolean);

  function ipToInt(ip){
    return ip.split('.').reduce((acc,oct)=> (acc<<8) + parseInt(oct,10), 0) >>> 0;
  }
  function cidrContains(cidr, ip){
    if (cidr.indexOf(':') !== -1) return false;
    const [net, mask] = cidr.split('/');
    const netInt = ipToInt(net);
    const ipInt = ipToInt(ip);
    const maskInt = mask===""? 0 : (~0 << (32 - parseInt(mask,10))) >>> 0;
    return (netInt & maskInt) === (ipInt & maskInt);
  }
  const ipsBehindCF = ipv4.filter(ip => cfRanges.some(r => cidrContains(r, ip)));

  const nsUsesCloudflare = nameservers.some(ns => ns.endsWith('ns.cloudflare.com') || ns.includes('cloudflare'));

  const headerIndications = [];
  if (httpInfo.headers['server'] && httpInfo.headers['server'].toLowerCase().includes('cloudflare')) headerIndications.push('server: cloudflare');
  if (httpInfo.headers['cf-ray']) headerIndications.push('cf-ray header present');
  if (httpInfo.headers['cf-cache-status']) headerIndications.push('cf-cache-status header present');

  const inference = {
    domain,
    resolved_ips: ipv4,
    nameservers,
    headerHints: headerIndications,
    ips_in_cloudflare_ranges: ipsBehindCF,
    ns_using_cloudflare: nsUsesCloudflare,
    likely_using_cloudflare: (nsUsesCloudflare || headerIndications.length>0 || ipsBehindCF.length>0)
  };

  return new Response(JSON.stringify(inference, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}