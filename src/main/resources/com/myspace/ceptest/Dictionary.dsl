[condition]Rule for Transactions over a time period=import fraud.analysis.demo.transaction.Transaction;import fraud.analysis.demo.transaction.CEPFraud;declare Transaction @role( event )  @timestamp( timestamp ) end
[condition]when=when
[condition]Accumulate on Transaction with "{transactionType}" and "{merchantType}"=accumulate ($b:Transaction(transactionType == "{transactionType}", merchantType=="{merchantType}")  from entry-point Transactions;
[condition]Over time period {t}=over window:time({t}m)
[condition]Number of Transactions are greater than {txn}=$number: count($b),$list: collectList($b);$number > {txn})$c2: Transaction() from $list
[consequence]then=then
[consequence]insert fraud with reason "{fraudReason}"=CEPFraud cepFraud = new CEPFraud();cepFraud.setTransaction($c2);cepFraud.setFraudReason("{fraudReason}");insert(cepFraud);