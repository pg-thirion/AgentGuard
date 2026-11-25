// Synthetic handlers only. No real email, shell, filesystem or insurance system access.
export const tools = {
  read_claim: async ({claimId}) => ({claimId,status:'Under review',source:'synthetic'}),
  lookup_policy: async ({policyId}) => ({policyId,status:'Active',source:'synthetic'}),
  send_email: async () => ({sent:false,source:'synthetic'}),
  run_shell: async () => ({executed:false,source:'synthetic'}),
  delete_record: async () => ({deleted:false,source:'synthetic'})
};
export const scenarios = [
  {label:'Legitimate claim lookup',agent:'claims-agent',tool:'read_claim',args:{claimId:'CLM-1042'}},
  {label:'Attempted shell execution',agent:'claims-agent',tool:'run_shell',args:{command:'example'}},
  {label:'Email for review',agent:'claims-agent',tool:'send_email',args:{recipient:'review@example.test',subject:'Review claim'}},
  {label:'Unauthorised recipient',agent:'claims-agent',tool:'send_email',args:{recipient:'external@example.test',subject:'Review claim'}},
  {label:'Cross-agent access',agent:'support-agent',tool:'read_claim',args:{claimId:'CLM-1042'}},
  {label:'Unexpected argument',agent:'claims-agent',tool:'read_claim',args:{claimId:'CLM-1042',includeSecrets:true}},
  {label:'Record deletion',agent:'claims-agent',tool:'delete_record',args:{}},
  {label:'Support policy lookup',agent:'support-agent',tool:'lookup_policy',args:{policyId:'POL-204'}}
];
