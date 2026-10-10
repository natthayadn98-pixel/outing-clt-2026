import { createClient } from 'npm:@supabase/supabase-js@2';
const allowedOrigin = Deno.env.get('ALLOWED_ORIGIN') || '';
function cors(origin: string) {
  return {
    'Access-Control-Allow-Origin': origin === allowedOrigin ? origin : allowedOrigin,
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json', 'Vary': 'Origin',
  };
}
Deno.serve(async (req) => {
  const origin = req.headers.get('origin') || '';
  const headers = cors(origin);
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers });
  if (!allowedOrigin || origin !== allowedOrigin) return reply({error:'origin_not_allowed'},403);
  if (req.method === 'OPTIONS') return new Response(null,{headers});
  if (req.method !== 'POST') return reply({error:'method_not_allowed'},405);
  try {
    const { idToken, action, employeeCode, enrollmentCode } = await req.json();
    if (typeof idToken !== 'string' || !idToken || idToken.length > 10000 || !['status','bind_pin'].includes(action))
      return reply({error:'invalid_request'},400);
    const channelId = Deno.env.get('LINE_CHANNEL_ID');
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!channelId || !supabaseUrl || !serviceKey) return reply({error:'server_not_configured'},503);
    const verifyResponse = await fetch('https://api.line.me/oauth2/v2.1/verify', {
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({id_token:idToken,client_id:channelId})
    });
    if (!verifyResponse.ok) return reply({error:'invalid_line_token'},401);
    const identity = await verifyResponse.json();
    if (typeof identity.sub !== 'string' || identity.aud !== channelId ||
      Number(identity.exp) <= Math.floor(Date.now()/1000)) return reply({error:'invalid_line_token'},401);
    const db = createClient(supabaseUrl,serviceKey,{auth:{persistSession:false}});
    if (action === 'status') {
      const {data,error} = await db.from('employee_line_bindings').select('employee_code')
        .eq('line_user_id',identity.sub).maybeSingle();
      if (error) return reply({error:'database_error'},500);
      return reply({verified:true,linked:!!data,employeeCode:data?.employee_code ?? null});
    }
    if (typeof employeeCode !== 'string' || !/^\d{6}$/.test(employeeCode))
      return reply({error:'invalid_employee_code'},400);
    const {data,error} = await db.rpc('bind_employee_line_pin_once',{
      p_employee_code:employeeCode,p_line_user_id:identity.sub
    });
    if (error) { console.error('bind_pin failed',error.code); return reply({error:'database_error'},500); }
    if (data === 'bound' || data === 'already_bound')
      return reply({linked:true,employeeCode,result:data});
    const status = data === 'rate_limited' ? 429 : data === 'employee_not_found' ? 404 : 409;
    return reply({linked:false,error:data || 'bind_failed'},status);
  } catch { return reply({error:'invalid_request'},400); }
});
