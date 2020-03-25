package Classes::CheckPoint::Firewall1::Component::VpnSessions;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(cpvIKECurrRespSAs cpvIKEMaxConncurRespSAs)));
}

sub check {
  my ($self) = @_;
  $self->add_info(sprintf '%s vpn sessions (security associations) used', $self->{cpvIKECurrRespSAs});
  $self->set_thresholds(warning => 180, critical => 200);
  $self->add_message($self->check_thresholds($self->{cpvIKECurrRespSAs}));
  $self->add_perfdata(
      label => 'vpn_sessions',
      value => $self->{cpvIKECurrRespSAs},
      min => 0,
      max => $self->{cpvIKEMaxConncurRespSAs},
  );
}
